"""
requests_api.py — Huduma Murang'a Public Service Request System
County 021 | Murang'a County Government

Architecture & Core Responsibilities:
    · Blueprint Registration: Exposes all service request lifecycle operations, admin analytics,
      CSV audit reporting, and citizen directory account controls under /api/*.
    · Defense-in-Depth Security Controls:
        - Strict Whitelisting: Server-side validation of categories, sub-counties, priorities, and statuses.
        - Magic-Byte File Validation: Reads initial bytes to verify true JPEG/PNG signatures before saving.
        - IDOR Ownership Protection: Verifies request ownership (user_id == session["user_id"]) before
          allowing citizens to rate or clear tickets.
        - OWASP CSV Formula Injection Defense: Escapes cells starting with '=', '+', '-', or '@'.
        - DPA PII Compliance: Public ticket lookup (/track/<id>) completely omits personal identity data.
    · Automatic Department Routing: Maps requests to dedicated county agencies (MUWASCO, Energy,
      Sanitation, Roads) based on category and sub-county.
    · Asynchronous SMTP Notification Engine: Non-blocking daemon threads dispatch professional HTML
      status updates to citizens upon ticket creation and status changes.
    · Immutable Audit Logging: Every state transition is recorded with timestamp, admin ID, remarks,
      and client IP address.

Author : Shem Imani (Lead Full-Stack GovTech Engineer)
Created: 2026-10-18
"""

import csv
import io
import os
import secrets
import smtplib
import threading
from datetime import datetime, timezone
from email.message import EmailMessage

# ─────────────────────────────────────────────────────────────────────────────
# 12-Factor Configuration: Load .env variables with safe fallback
# ─────────────────────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flask import (
    Blueprint,
    Response,
    jsonify,
    request,
    send_file,
    session,
)
from werkzeug.utils import secure_filename

from auth import admin_required, login_required
from database import get_db_connection

# ---------------------------------------------------------------------------
# Live Gmail SMTP Configuration (Non-blocking background delivery)
# ---------------------------------------------------------------------------
SMTP_USER: str = os.environ.get("SMTP_EMAIL", os.environ.get("GMAIL_USER", "")).strip()
SMTP_PASS: str = os.environ.get("SMTP_APP_PASSWORD", os.environ.get("GMAIL_APP_PASSWORD", "")).replace(" ", "").strip()
SMTP_HOST: str = os.environ.get("SMTP_SERVER", os.environ.get("SMTP_HOST", "smtp.gmail.com")).strip()
SMTP_PORT: int = int(os.environ.get("SMTP_PORT", 465))
HELPLINE_NUMBER: str = os.environ.get("HELPLINE_NUMBER", "0119706796").strip()

# ---------------------------------------------------------------------------
# Blueprint
# ---------------------------------------------------------------------------

requests_bp = Blueprint("requests_api", __name__, url_prefix="/api")

# ---------------------------------------------------------------------------
# A. Server-side validation whitelists
# ---------------------------------------------------------------------------
# Using lists (not sets) to preserve display order in frontend dropdowns.

VALID_CATEGORIES: list[str] = [
    "Water & Sewerage",
    "Streetlight & Electrical",
    "Garbage & Sanitation",
    "Roads & Drainage",
]

VALID_SUB_COUNTIES: list[str] = [
    "Kiharu",
    "Mathioya",
    "Kangema",
    "Gatanga",
    "Maragua",
    "Kandara",
    "Kigumo",
]

VALID_PRIORITIES: list[str] = ["Normal", "High", "Urgent"]

VALID_STATUSES: list[str] = ["Pending", "In Progress", "Resolved"]

# Allowed image MIME extensions and their corresponding magic-byte signatures
_ALLOWED_EXTENSIONS: frozenset[str] = frozenset({"png", "jpg", "jpeg", "webp"})

# Upload directory relative to the project root (created by app.py on startup)
_UPLOAD_DIR: str = os.path.join("static", "uploads")

# Ticket format constants
_TICKET_PREFIX: str = "MCG-021"
_TICKET_YEAR: int = datetime.now(timezone.utc).year


# ---------------------------------------------------------------------------
# B. Helper 1 — Murang'a Smart Agency Router
# ---------------------------------------------------------------------------


def get_assigned_agency(category: str, sub_county: str) -> str:
    """Route a service request to the correct Murang'a County utility/agency.

    The assignment is computed entirely on the server to prevent a malicious
    client from specifying an arbitrary agency in the request payload.

    Routing logic follows the actual Murang'a County water concession map:
        - MUWASCO   covers Kiharu sub-county (largest urban centre, Murang'a Town)
        - GATAMATHI covers Mathioya (Gatamathi WSP)
        - KAHUTI    covers Kangema (Kahuti Water Company)
        - Gatanga Community Water Scheme covers Gatanga
        - MUSWASCO  covers the southern sub-counties (Maragua, Kandara, Kigumo)

    Streetlighting is split between Murang'a Municipality and the newer
    Kenol-Kangari Municipality that serves the south-east corridor.

    Args:
        category  : One of VALID_CATEGORIES.
        sub_county: One of VALID_SUB_COUNTIES.

    Returns:
        A non-empty string naming the responsible county agency.
    """
    if category == "Water & Sewerage":
        return {
            "Kiharu":    "MUWASCO Technical Team",
            "Mathioya":  "GATAMATHI Water & Sanitation",
            "Kangema":   "KAHUTI Water Company",
            "Gatanga":   "Gatanga Community Water Scheme",
            "Maragua":   "MUSWASCO (Murang'a South Water)",
            "Kandara":   "MUSWASCO (Murang'a South Water)",
            "Kigumo":    "MUSWASCO (Murang'a South Water)",
        }.get(sub_county, "Murang'a Water Services Board")

    if category == "Streetlight & Electrical":
        if sub_county == "Kiharu":
            return "Murang'a Municipality Electrical Unit"
        if sub_county in {"Maragua", "Kandara", "Kigumo"}:
            return "Kenol-Kangari Municipality Electrical Unit"
        return "County Energy & Streetlighting Unit"

    if category == "Garbage & Sanitation":
        return "Directorate of Environment & Solid Waste"

    if category == "Roads & Drainage":
        return "Directorate of Roads & Infrastructure"

    # Fallback — should never be reached if validation is applied first
    return "Murang'a County Government"


# ---------------------------------------------------------------------------
# C. Helper 2 — Secure Optional Image Upload
# ---------------------------------------------------------------------------

# Magic-byte signatures for supported image formats.
# Validating file content (not just extension) prevents rename attacks where
# a malicious actor uploads a PHP/Python script with a .jpg extension.
_MAGIC_BYTES: dict[str, bytes] = {
    "jpeg": b"\xff\xd8\xff",
    "png":  b"\x89PNG\r\n\x1a\n",
    "webp_riff": b"RIFF",  # WebP starts with RIFF....WEBP
}


def _is_valid_image_magic(file_obj) -> bool:
    """Check the first bytes of a file object against known image signatures.

    Args:
        file_obj: A file-like object with a ``read()`` and ``seek()`` method
                  (e.g. the FileStorage object from Flask's request.files).

    Returns:
        True if the header matches a supported image format, False otherwise.
    """
    header = file_obj.read(12)
    file_obj.seek(0)  # Reset so the caller can still read / save the full file

    if header[:3] == _MAGIC_BYTES["jpeg"]:
        return True
    if header[:8] == _MAGIC_BYTES["png"]:
        return True
    # WebP: bytes 0-3 == "RIFF" AND bytes 8-12 == "WEBP"
    if header[:4] == _MAGIC_BYTES["webp_riff"] and header[8:12] == b"WEBP":
        return True

    return False


def save_optional_image(file_obj) -> str | None:
    """Securely validate and save an uploaded image, or return None gracefully.

    Security measures applied (defence-in-depth):
        1. Extension whitelist   — only png/jpg/jpeg/webp accepted.
        2. Magic-byte validation — actual file content must match a known image
                                   header, blocking disguised script uploads.
        3. secure_filename()     — strips path traversal sequences (../../etc.)
                                   and non-ASCII characters from the filename.
        4. Random prefix         — timestamp + secrets.token_hex(3) prevents
                                   filename guessing and cache-poisoning.
        5. Stored under /static/uploads/ — outside any code-execution path.

    Args:
        file_obj: A Werkzeug ``FileStorage`` object from ``request.files``, or
                  ``None`` / empty filename if no file was attached.

    Returns:
        The public URL path string ``/static/uploads/<name>`` on success,
        or ``None`` if no file was provided or validation fails.

    Raises:
        ValueError: If the extension is not allowed or magic bytes don't match,
                    with a user-friendly message the endpoint can forward.
    """
    # Gracefully handle absent or empty file fields
    if file_obj is None or file_obj.filename == "":
        return None

    original_name = file_obj.filename
    ext = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""

    if ext not in _ALLOWED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file type '.{ext}'. "
            "Allowed types: PNG, JPG, JPEG, WEBP."
        )

    if not _is_valid_image_magic(file_obj):
        raise ValueError(
            "File content does not match its extension. "
            "Please upload a genuine PNG, JPEG, or WEBP image."
        )

    # Sanitize filename and add an unpredictable prefix
    safe_name  = secure_filename(original_name)
    timestamp  = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    rand_hex   = secrets.token_hex(3)                 # 6-char random hex
    final_name = f"{timestamp}_{rand_hex}_{safe_name}"

    save_path = os.path.join(_UPLOAD_DIR, final_name)
    file_obj.save(save_path)

    return f"/static/uploads/{final_name}"


# ---------------------------------------------------------------------------
# C. Helper 2 — Non-blocking Live Gmail SMTP Email Notification Engine
# ---------------------------------------------------------------------------


def send_ticket_email(
    citizen_name: str,
    recipient_email: str,
    ticket_id: str,
    category: str,
    location: str,
    assigned_unit: str,
    status: str = "Pending",
    admin_remarks: str = "",
) -> dict:
    """Send an official Murang'a County service request email notification.

    Constructs an authoritative Aberdare Forest Green (#064e3b) and Harvest
    Gold (#f59e0b) HTML template with a clean plain-text fallback, and dispatches
    it asynchronously in a daemon thread via Gmail SMTP.

    Thread safety & resiliency:
        The SMTP handshake and network transmission happen entirely inside
        a background daemon thread (`threading.Thread(target=_send_async, daemon=True)`).
        Any connection timeout, TLS handshake, or authentication issue is logged
        gracefully without delaying or failing the client's HTTP response.

    Returns:
        JSON-serializable receipt dict for client confirmation:
        {
            "recipient_email": recipient_email,
            "subject": subject,
            "status": status,
            "assigned_unit": assigned_unit,
            "delivery_mode": "Live Gmail SMTP (configured sender) or Local Simulated Dispatch"
        }
    """
    subject = f"[{ticket_id}] Murang'a County Service Request Update — {status}"

    # Status color code for the HTML badge
    badge_bg = "#d97706" if status == "Pending" else ("#0284c7" if status == "In Progress" else "#15803d")

    # Plain text fallback
    plain_text = f"""HUDUMA MURANG'A — PUBLIC SERVICE REQUEST SYSTEM
"Kamũingĩ Koyaga Ndĩrĩ" — Unity is Strength

Dear {citizen_name},

This is an official confirmation from the Murang'a County Government regarding your municipal service request.

TICKET SUMMARY:
--------------------------------------------------
Ticket Reference : {ticket_id}
Service Category : {category}
Ward / Location  : {location}
Assigned Agency  : {assigned_unit}
Current Status   : {status}
--------------------------------------------------
"""
    if admin_remarks:
        plain_text += f"\nOFFICIAL COUNTY OFFICER REMARKS:\n{admin_remarks}\n"

    plain_text += f"""
You can track the live progress of your ticket anytime on the Huduma Murang'a portal:
http://127.0.0.1:5000/

Kamũingĩ Koyaga Ndĩrĩ — Murang'a County Government | Helpline: 0119706796
Murang'a County Government, P.O. Box 52-10200, Murang'a, Kenya.
Data protected under the Kenya Data Protection Act, 2019.
"""

    # Rich responsive HTML template
    remarks_html = ""
    if admin_remarks:
        remarks_html = f"""
        <div style="background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 14px 16px; border-radius: 8px; margin: 20px 0;">
            <p style="margin: 0 0 6px 0; font-size: 13px; font-weight: bold; color: #78350f; text-transform: uppercase; letter-spacing: 0.5px;">
                Official County Officer Remarks
            </p>
            <p style="margin: 0; font-size: 14px; color: #451a03; line-height: 1.5;">
                {admin_remarks}
            </p>
        </div>
        """

    html_content = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{subject}</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f5f5f4; font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #1c1917;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f5f5f4; padding: 30px 15px;">
        <tr>
            <td align="center">
                <table role="presentation" width="100%" style="max-width: 600px; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 20px rgba(6, 78, 59, 0.08); border: 1px solid #e7e5e4;" cellspacing="0" cellpadding="0">
                    <!-- Institutional Header Bar -->
                    <tr>
                        <td style="background-color: #064e3b; padding: 24px 30px; border-bottom: 4px solid #f59e0b;">
                            <table width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td>
                                        <h1 style="margin: 0; font-size: 20px; font-weight: bold; color: #ffffff; letter-spacing: -0.5px;">
                                            Huduma Murang'a
                                        </h1>
                                        <p style="margin: 4px 0 0 0; font-size: 12px; color: #a7f3d0; letter-spacing: 0.5px;">
                                            MURANG'A COUNTY GOVERNMENT e-SERVICES
                                        </p>
                                    </td>
                                    <td align="right" style="vertical-align: middle;">
                                        <p style="margin: 0; font-size: 12px; color: #fde68a; font-style: italic;">
                                            "Kamũingĩ Koyaga Ndĩrĩ"
                                        </p>
                                        <p style="margin: 2px 0 0 0; font-size: 10px; color: #6ee7b7;">
                                            Unity is Strength
                                        </p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Body Content -->
                    <tr>
                        <td style="padding: 30px;">
                            <h2 style="margin: 0 0 12px 0; font-size: 18px; color: #064e3b; font-weight: 700;">
                                Service Request Notification
                            </h2>
                            <p style="margin: 0 0 20px 0; font-size: 14px; line-height: 1.6; color: #44403c;">
                                Dear <strong>{citizen_name}</strong>,<br>
                                An official update has been logged on your public service request submitted to Murang'a County.
                            </p>

                            <!-- Ticket Reference Card -->
                            <table width="100%" cellspacing="0" cellpadding="0" style="background-color: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 12px; padding: 18px; margin-bottom: 20px;">
                                <tr>
                                    <td>
                                        <p style="margin: 0; font-size: 11px; font-weight: 600; color: #166534; text-transform: uppercase; letter-spacing: 0.5px;">
                                            Ticket Reference
                                        </p>
                                        <p style="margin: 4px 0 0 0; font-family: 'JetBrains Mono', monospace; font-size: 20px; font-weight: bold; color: #064e3b; letter-spacing: 0.5px;">
                                            {ticket_id}
                                        </p>
                                    </td>
                                    <td align="right">
                                        <span style="display: inline-block; background-color: {badge_bg}; color: #ffffff; font-size: 12px; font-weight: 600; padding: 6px 14px; border-radius: 20px;">
                                            {status}
                                        </span>
                                    </td>
                                </tr>
                            </table>

                            <!-- Details Table -->
                            <table width="100%" cellspacing="0" cellpadding="8" style="font-size: 13px; color: #292524; border-collapse: collapse; margin-bottom: 20px;">
                                <tr style="border-bottom: 1px solid #f5f5f4;">
                                    <td style="color: #78716c; width: 35%; padding: 8px 0;">Service Category:</td>
                                    <td style="font-weight: 600; padding: 8px 0;">{category}</td>
                                </tr>
                                <tr style="border-bottom: 1px solid #f5f5f4;">
                                    <td style="color: #78716c; padding: 8px 0;">Ward / Location:</td>
                                    <td style="font-weight: 600; padding: 8px 0;">{location}</td>
                                </tr>
                                <tr>
                                    <td style="color: #78716c; padding: 8px 0;">Assigned Agency:</td>
                                    <td style="font-weight: 700; color: #064e3b; padding: 8px 0;">{assigned_unit}</td>
                                </tr>
                            </table>

                            {remarks_html}

                            <div style="text-align: center; margin-top: 25px; margin-bottom: 10px;">
                                <a href="http://127.0.0.1:5000/" style="display: inline-block; background-color: #047857; color: #ffffff; text-decoration: none; font-size: 13px; font-weight: 600; padding: 12px 26px; border-radius: 10px; box-shadow: 0 2px 8px rgba(4, 120, 87, 0.25);">
                                    Track Live on Huduma Murang'a Portal
                                </a>
                            </div>
                        </td>
                    </tr>

                    <!-- Institutional Footer -->
                    <tr>
                        <td style="background-color: #f5f5f4; padding: 20px 30px; border-top: 1px solid #e7e5e4; text-align: center;">
                            <p style="margin: 0; font-size: 12px; color: #78716c;">
                                <strong>Murang'a County Government</strong><br>
                                Kamũingĩ Koyaga Ndĩrĩ — Murang'a County Government | Helpline: 0119706796
                            </p>
                            <p style="margin: 8px 0 0 0; font-size: 11px; color: #a8a29e;">
                                This is an automated public service notification. Data protected under the Kenya Data Protection Act, 2019.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""

    def _send_async():
        """Background thread worker that communicates with Gmail SMTP."""
        try:
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = f"Huduma Murang'a <{SMTP_USER}>"
            msg["To"] = recipient_email
            msg.set_content(plain_text)
            msg.add_alternative(html_content, subtype="html")

            if SMTP_PORT == 465:
                with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                    server.login(SMTP_USER, SMTP_PASS)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                    server.starttls()
                    server.login(SMTP_USER, SMTP_PASS)
                    server.send_message(msg)

            print(f"[SMTP] Successfully dispatched email for {ticket_id} to {recipient_email}")
        except Exception as exc:
            # Resiliency: Never crash or interrupt the parent thread
            print(f"[SMTP Warning] Could not dispatch email to {recipient_email}: {exc}")

    # Fire and forget in daemon thread
    threading.Thread(target=_send_async, daemon=True).start()

    return {
        "recipient_email": recipient_email,
        "subject": subject,
        "status": status,
        "assigned_unit": assigned_unit,
        "delivery_mode": f"Live Gmail SMTP ({SMTP_USER})",
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    """Return current UTC time as an ISO-8601 string (matches database.py)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _get_ip() -> str:
    """Extract real client IP, honoring X-Forwarded-For behind a proxy."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _generate_ticket_id(conn) -> str:
    """Generate a unique ticket ID, retrying on the rare collision.

    Format: MCG-021-<YEAR>-<4-char HEX from secrets.token_hex(2)>

    Using ``secrets.token_hex`` (CSPRNG) makes ticket IDs unpredictable,
    preventing enumeration of other citizens' tickets via sequential guessing.
    The collision retry loop is a safety net; with 65 536 combinations per year
    and modest county traffic the probability is negligible.

    Args:
        conn: An open ``sqlite3.Connection`` used for the uniqueness check.

    Returns:
        A ticket ID string guaranteed to be unique in the database.
    """
    for _ in range(10):                               # up to 10 retries
        suffix  = secrets.token_hex(2).upper()        # e.g. "A3F7"
        ticket  = f"{_TICKET_PREFIX}-{_TICKET_YEAR}-{suffix}"
        exists  = conn.execute(
            "SELECT 1 FROM service_requests WHERE ticket_id = ?", (ticket,)
        ).fetchone()
        if not exists:
            return ticket
    # Extremely unlikely; raise so the caller returns a 500 rather than
    # silently inserting a duplicate
    raise RuntimeError("Could not generate a unique ticket ID after 10 attempts.")


def _row_to_dict(row) -> dict:
    """Convert a ``sqlite3.Row`` to a plain ``dict`` for JSON serialisation.

    sqlite3.Row objects support dict() conversion; this thin wrapper makes
    intent explicit and provides a single place to add field post-processing.
    """
    return dict(row)


# ===========================================================================
# D. Endpoints
# ===========================================================================

# ---------------------------------------------------------------------------
# 1. GET /api/requests — list requests (citizen sees own; admin sees all)
# ---------------------------------------------------------------------------


@requests_bp.route("/requests", methods=["GET"])
@login_required
def list_requests(current_user: dict):
    """Retrieve service requests based on the caller's role.

    Citizen view:
        Returns only the caller's own requests, newest first.
        No filters are applicable — a citizen cannot query other users' data.

    Admin view:
        Returns all requests with an enriched LEFT JOIN that adds the
        submitting citizen's name, email, and phone directly to each row,
        saving a round-trip for the dashboard table.

        Supports four optional query-string filters:
            ?status=     — exact match against VALID_STATUSES
            ?category=   — exact match against VALID_CATEGORIES
            ?sub_county= — exact match against VALID_SUB_COUNTIES
            ?search=     — substring match on ticket_id, location, description

    Security:
        All filter values are validated against server-side whitelists before
        being bound to SQL parameters, preventing both injection and unexpected
        data leakage via crafted filter values.

    Returns:
        200 OK — { "requests": [ … ] }
    """
    conn = get_db_connection()
    role = current_user["role"]

    if role == "citizen":
        # Citizens may only see their own submissions — hard-coded WHERE clause
        rows = conn.execute(
            """
            SELECT *
            FROM   service_requests
            WHERE  user_id = ?
            ORDER  BY id DESC
            """,
            (current_user["id"],),
        ).fetchall()
        conn.close()
        return jsonify({"requests": [_row_to_dict(r) for r in rows]}), 200

    # ── Admin path ────────────────────────────────────────────────────────────
    # Build a dynamic WHERE clause from validated query parameters.
    # Conditions and bind-values are accumulated separately so the final
    # query is assembled safely without string interpolation of user input.
    conditions: list[str] = []
    params: list          = []

    status     = request.args.get("status",     "").strip()
    category   = request.args.get("category",   "").strip()
    priority   = request.args.get("priority",   "").strip()
    sub_county = request.args.get("sub_county", "").strip()
    search     = request.args.get("search",     "").strip()

    if status and status in VALID_STATUSES:
        conditions.append("sr.status = ?")
        params.append(status)

    if category and category in VALID_CATEGORIES:
        conditions.append("sr.category = ?")
        params.append(category)

    if priority and priority in VALID_PRIORITIES:
        conditions.append("sr.priority = ?")
        params.append(priority)

    if sub_county and sub_county in VALID_SUB_COUNTIES:
        conditions.append("sr.sub_county = ?")
        params.append(sub_county)

    if search:
        # LIKE pattern uses % wildcards; the value itself is bound as a
        # parameter — SQLite escapes it, preventing injection.
        like_pattern = f"%{search}%"
        conditions.append(
            "(sr.ticket_id LIKE ? OR sr.location LIKE ? OR sr.description LIKE ?)"
        )
        params.extend([like_pattern, like_pattern, like_pattern])

    where_sql = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    rows = conn.execute(
        f"""
        SELECT sr.*,
               u.full_name  AS citizen_name,
               u.email      AS citizen_email,
               u.phone      AS citizen_phone
        FROM   service_requests sr
        LEFT JOIN users u ON u.id = sr.user_id
        {where_sql}
        ORDER  BY sr.id DESC
        """,
        params,
    ).fetchall()
    conn.close()

    return jsonify({"requests": [_row_to_dict(r) for r in rows]}), 200


# ---------------------------------------------------------------------------
# 2. POST /api/requests — submit a new service request
# ---------------------------------------------------------------------------


@requests_bp.route("/requests", methods=["POST"])
@login_required
def submit_request(current_user: dict):
    """Submit a new municipal service request on behalf of the logged-in citizen.

    Accepts multipart/form-data (with optional image) OR application/json.
    Priority is given to form data; if ``request.content_type`` does not
    include 'multipart', the endpoint falls back to ``request.get_json()``.

    Validation:
        · category   — must be in VALID_CATEGORIES
        · sub_county — must be in VALID_SUB_COUNTIES
        · location   — required, 5–200 chars
        · description — required, 10–1000 chars
        · priority   — optional, defaults to 'Normal', must be in VALID_PRIORITIES

    Atomicity:
        The INSERT into ``service_requests`` and the INSERT into ``audit_logs``
        execute inside a single ``with conn:`` transaction block, which SQLite
        rolls back automatically if either statement raises an exception.

    Returns:
        201 Created  — { "message": "…", "request": { … } }
        400 Bad Request — validation errors
        500 Internal Server Error — ticket collision or DB error
    """
    ct = request.content_type or ""
    if "multipart" in ct or "form" in ct:
        data = request.form.to_dict()
        image_file = request.files.get("image")
    else:
        data       = request.get_json(silent=True) or {}
        image_file = None

    # ── Field extraction ──────────────────────────────────────────────────────
    category    = (data.get("category",    "") or "").strip()
    sub_county  = (data.get("sub_county",  "") or "").strip()
    location    = (data.get("location",    "") or "").strip()
    description = (data.get("description", "") or "").strip()
    priority    = (data.get("priority",    "Normal") or "Normal").strip()

    # ── Validation ────────────────────────────────────────────────────────────
    errors: list[str] = []

    if category not in VALID_CATEGORIES:
        errors.append(
            f"Category must be one of: {', '.join(VALID_CATEGORIES)}."
        )
    if sub_county not in VALID_SUB_COUNTIES:
        errors.append(
            f"Sub-county must be one of: {', '.join(VALID_SUB_COUNTIES)}."
        )
    if not location or len(location) < 5:
        errors.append("Location must be at least 5 characters.")
    if len(location) > 200:
        errors.append("Location must not exceed 200 characters.")
    if not description or len(description) < 10:
        errors.append("Description must be at least 10 characters.")
    if len(description) > 1000:
        errors.append("Description must not exceed 1000 characters.")
    if priority not in VALID_PRIORITIES:
        errors.append(
            f"Priority must be one of: {', '.join(VALID_PRIORITIES)}."
        )

    if errors:
        return jsonify({"error": "Validation failed.", "details": errors}), 400

    # ── Image upload (optional) ───────────────────────────────────────────────
    image_url: str | None = None
    try:
        image_url = save_optional_image(image_file)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    # ── Agency routing (server-side) ──────────────────────────────────────────
    assigned_unit = get_assigned_agency(category, sub_county)
    now           = _now_iso()
    ip            = _get_ip()

    # ── Atomic DB transaction ─────────────────────────────────────────────────
    conn = get_db_connection()
    try:
        ticket_id = _generate_ticket_id(conn)

        with conn:                                    # auto-commit or rollback
            conn.execute(
                """
                INSERT INTO service_requests (
                    ticket_id, user_id, category, sub_county, location,
                    description, priority, image_url, assigned_unit,
                    status, admin_remarks, citizen_rating,
                    created_at, updated_at
                ) VALUES (
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    'Pending', '', NULL,
                    ?, ?
                )
                """,
                (
                    ticket_id, current_user["id"], category, sub_county, location,
                    description, priority, image_url, assigned_unit,
                    now, now,
                ),
            )

            conn.execute(
                """
                INSERT INTO audit_logs
                    (actor_name, actor_email, actor_role, ticket_id, action, ip_address, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    current_user["full_name"],
                    current_user.get("email") or session.get("email", ""),
                    current_user["role"],
                    ticket_id,
                    f"Citizen submitted new request — category: {category}, "
                    f"sub-county: {sub_county}, priority: {priority}",
                    ip,
                    now,
                ),
            )

        # Fetch the full inserted row to return complete data to the client
        new_request = conn.execute(
            "SELECT * FROM service_requests WHERE ticket_id = ?", (ticket_id,)
        ).fetchone()

        # Query user details to send instant email receipt
        user_row = conn.execute(
            "SELECT full_name, email FROM users WHERE id = ?", (current_user["id"],)
        ).fetchone()

    except RuntimeError as exc:
        conn.close()
        return jsonify({"error": str(exc)}), 500
    finally:
        conn.close()

    # Dispatch email confirmation asynchronously (non-blocking)
    recipient_email = user_row["email"] if user_row else current_user.get("email", "")
    citizen_name    = user_row["full_name"] if user_row else current_user.get("full_name", "Citizen")

    email_receipt = send_ticket_email(
        citizen_name=citizen_name,
        recipient_email=recipient_email,
        ticket_id=ticket_id,
        category=category,
        location=f"{sub_county}, {location}",
        assigned_unit=assigned_unit,
        status="Pending",
        admin_remarks="",
    )

    return (
        jsonify(
            {
                "message": (
                    f"Your request has been submitted. "
                    f"Track it using ticket ID: {ticket_id}"
                ),
                "request": _row_to_dict(new_request),
                "email_notification": email_receipt,
            }
        ),
        201,
    )


# ---------------------------------------------------------------------------
# 3. PATCH /api/requests/<req_id>/status — admin updates request status
# ---------------------------------------------------------------------------


@requests_bp.route("/requests/<int:req_id>/status", methods=["PATCH"])
@login_required
@admin_required
def update_status(current_user: dict, req_id: int):
    """Update the status and optional admin remarks on a service request.

    Only admin-role users may call this endpoint (enforced by @admin_required).

    The old status is read before the UPDATE so the audit log entry can record
    a human-readable ``"Status changed from <old> to <new>"`` message that
    makes the log self-explanatory without joins.

    Both the UPDATE and the audit INSERT execute inside a single SQLite
    transaction; if either fails, both are rolled back.

    Args:
        req_id: The integer primary-key of the service request row.

    Request JSON:
        status       (str, required) — must be in VALID_STATUSES
        admin_remarks (str, optional) — free-text note shown to the citizen

    Returns:
        200 OK          — { "message": "…", "request": { … } }
        400 Bad Request — invalid or missing status
        404 Not Found   — no request with that ID
    """
    data          = request.get_json(silent=True) or {}
    new_status    = (data.get("status",        "") or "").strip()
    admin_remarks = (data.get("admin_remarks", "") or "").strip()

    if new_status not in VALID_STATUSES:
        return (
            jsonify(
                {
                    "error": (
                        f"Invalid status '{new_status}'. "
                        f"Must be one of: {', '.join(VALID_STATUSES)}."
                    )
                }
            ),
            400,
        )

    conn = get_db_connection()
    row  = conn.execute(
        """
        SELECT sr.*,
               u.full_name AS citizen_name,
               u.email     AS citizen_email
        FROM   service_requests sr
        JOIN   users u ON u.id = sr.user_id
        WHERE  sr.id = ?
        """,
        (req_id,),
    ).fetchone()

    if not row:
        conn.close()
        return jsonify({"error": f"No service request found with ID {req_id}."}), 404

    old_status      = row["status"]
    ticket_id       = row["ticket_id"]
    category        = row["category"]
    sub_county      = row["sub_county"]
    location        = row["location"]
    clean_location  = f"{sub_county}, {location}"
    assigned_unit   = row["assigned_unit"]
    citizen_name    = row["citizen_name"]
    recipient_email = row["citizen_email"]
    now             = _now_iso()
    ip              = _get_ip()

    with conn:
        conn.execute(
            """
            UPDATE service_requests
            SET    status        = ?,
                   admin_remarks = ?,
                   updated_at    = ?
            WHERE  id = ?
            """,
            (new_status, admin_remarks, now, req_id),
        )

        conn.execute(
            """
            INSERT INTO audit_logs
                (actor_name, actor_email, actor_role, ticket_id, action, ip_address, timestamp)
            VALUES (?, ?, 'admin', ?, ?, ?, ?)
            """,
            (
                current_user["full_name"],
                current_user.get("email") or session.get("email", ""),
                ticket_id,
                f"Status changed from '{old_status}' to '{new_status}'"
                + (f"; Remarks: {admin_remarks}" if admin_remarks else ""),
                ip,
                now,
            ),
        )

    updated = conn.execute(
        "SELECT * FROM service_requests WHERE id = ?", (req_id,)
    ).fetchone()
    conn.close()

    # Dispatch email notification for status change (non-blocking)
    email_receipt = send_ticket_email(
        citizen_name=citizen_name,
        recipient_email=recipient_email,
        ticket_id=ticket_id,
        category=category,
        location=clean_location,
        assigned_unit=assigned_unit,
        status=new_status,
        admin_remarks=admin_remarks,
    )

    return (
        jsonify(
            {
                "message": (
                    f"Ticket {ticket_id} status updated: "
                    f"{old_status} -> {new_status}."
                ),
                "request": _row_to_dict(updated),
                "email_notification": email_receipt,
            }
        ),
        200,
    )


# ---------------------------------------------------------------------------
# 4. PATCH /api/requests/<req_id>/rate — citizen rates a resolved request
# ---------------------------------------------------------------------------


@requests_bp.route("/requests/<int:req_id>/rate", methods=["PATCH"])
@login_required
def rate_request(current_user: dict, req_id: int):
    """Allow a citizen to submit a 1-5 star satisfaction rating on their resolved request.

    Security — IDOR (Insecure Direct Object Reference) prevention:
        The endpoint verifies ``row["user_id"] == current_user["id"]`` before
        allowing any write.  A citizen who guesses another citizen's req_id
        cannot rate (or alter) that request.

    Business Rules:
        · Rating is only allowed when status == 'Resolved'.
        · Rating must be an integer in the range [1, 5].
        · Once set, a rating can be updated by the owning citizen (intentional
          UX choice — a citizen who initially rated in anger can revise).

    Args:
        req_id: Integer primary key of the service request.

    Request JSON:
        rating (int, required) — 1 to 5 inclusive

    Returns:
        200 OK          — { "message": "…", "citizen_rating": N }
        400 Bad Request — invalid rating value or request not yet resolved
        403 Forbidden   — IDOR: request belongs to a different citizen
        404 Not Found   — no request with that ID
    """
    data   = request.get_json(silent=True) or {}
    rating = data.get("rating")

    conn = get_db_connection()
    row  = conn.execute(
        "SELECT * FROM service_requests WHERE id = ?", (req_id,)
    ).fetchone()

    if not row:
        conn.close()
        return jsonify({"error": f"No service request found with ID {req_id}."}), 404

    # IDOR ownership check — must happen before any data is read or written
    if row["user_id"] != current_user["id"]:
        conn.close()
        return (
            jsonify({"error": "You can only rate your own service requests."}),
            403,
        )

    if row["status"] != "Resolved":
        conn.close()
        return (
            jsonify(
                {
                    "error": (
                        "Ratings can only be submitted once the request has been "
                        "marked as Resolved."
                    )
                }
            ),
            400,
        )

    # Validate rating value
    try:
        rating = int(rating)
    except (TypeError, ValueError):
        conn.close()
        return jsonify({"error": "Rating must be an integer between 1 and 5."}), 400

    if not (1 <= rating <= 5):
        conn.close()
        return jsonify({"error": "Rating must be between 1 (lowest) and 5 (highest)."}), 400

    now = _now_iso()
    ip  = _get_ip()

    with conn:
        conn.execute(
            "UPDATE service_requests SET citizen_rating = ?, updated_at = ? WHERE id = ?",
            (rating, now, req_id),
        )
        conn.execute(
            """
            INSERT INTO audit_logs
                (actor_name, actor_email, actor_role, ticket_id, action, ip_address, timestamp)
            VALUES (?, ?, 'citizen', ?, ?, ?, ?)
            """,
            (
                current_user["full_name"],
                current_user.get("email") or session.get("email", ""),
                row["ticket_id"],
                f"Citizen submitted satisfaction rating: {rating}/5",
                ip,
                now,
            ),
        )

    conn.close()
    return (
        jsonify(
            {
                "message": f"Thank you! Your {rating}-star rating has been recorded.",
                "citizen_rating": rating,
            }
        ),
        200,
    )


# ---------------------------------------------------------------------------
# 5. GET /api/requests/track/<ticket_id> — public ticket tracker (no login)
# ---------------------------------------------------------------------------


@requests_bp.route("/requests/track/<ticket_id>", methods=["GET"])
def track_ticket(ticket_id: str):
    """Look up a service request by its human-readable ticket ID.

    This is a **public** endpoint — no authentication is required — so that
    citizens can share a ticket link with family members or ward reps without
    needing an account.

    Kenya Data Protection Act (DPA) Compliance:
        Only non-PII tracking fields are returned.  The citizen's name, phone
        number, and email are NEVER included in the response, even though they
        exist in the database and are reachable via a JOIN.  This satisfies
        the DPA's data minimisation principle for unauthenticated endpoints.

    Args:
        ticket_id: Raw URL segment (will be normalised to uppercase, stripped).

    Returns:
        200 OK    — { "ticket": { public fields only } }
        404 Not Found — no matching ticket
    """
    # Normalise: trim whitespace and force uppercase to match stored format
    lookup_id = ticket_id.strip().upper()

    conn = get_db_connection()
    row  = conn.execute(
        """
        SELECT ticket_id, category, sub_county, location, priority,
               assigned_unit, status, admin_remarks,
               citizen_rating, created_at, updated_at
        FROM   service_requests
        WHERE  UPPER(ticket_id) = ?
        """,
        (lookup_id,),
    ).fetchone()
    conn.close()

    if not row:
        return (
            jsonify(
                {
                    "error": (
                        f"Ticket '{lookup_id}' not found. "
                        "Please check the ID and try again."
                    )
                }
            ),
            404,
        )

    return jsonify({"ticket": _row_to_dict(row)}), 200


# ---------------------------------------------------------------------------
# 6. GET /api/analytics — admin dashboard aggregate data
# ---------------------------------------------------------------------------


@requests_bp.route("/analytics", methods=["GET"])
@login_required
@admin_required
def get_analytics(current_user: dict):
    """Compute and return aggregate statistics for the admin dashboard.

    Uses SQL ``SUM(CASE WHEN ...)`` aggregation in a single query to calculate
    all status counts in one round-trip, which is more efficient than issuing
    separate COUNT queries per status.

    Returned shape:
        summary:
            total_cases       — all requests ever submitted
            open_cases        — Pending + In Progress combined
            pending_cases     — Pending only
            in_progress_cases — In Progress only
            resolved_cases    — Resolved only
            resolution_rate   — resolved / total * 100, rounded to 1 decimal
            avg_rating        — average citizen_rating (may be null)
        by_category:
            list of { category, count } ordered by count DESC
        by_sub_county:
            list of { sub_county, count } ordered by count DESC
        audit_logs:
            latest 25 audit log entries (newest first) for the activity feed

    Returns:
        200 OK — { "summary": {…}, "by_category": […], … }
    """
    conn = get_db_connection()

    # ── Single-query status aggregation ──────────────────────────────────────
    summary_row = conn.execute(
        """
        SELECT
            COUNT(*)                                                       AS total_cases,
            SUM(CASE WHEN status IN ('Pending','In Progress') THEN 1 ELSE 0 END)
                                                                           AS open_cases,
            SUM(CASE WHEN status = 'Pending'     THEN 1 ELSE 0 END)       AS pending_cases,
            SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END)       AS in_progress_cases,
            SUM(CASE WHEN status = 'Resolved'    THEN 1 ELSE 0 END)       AS resolved_cases,
            ROUND(
                100.0 * SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END)
                      / MAX(COUNT(*), 1),
                1
            )                                                              AS resolution_rate,
            ROUND(AVG(CASE WHEN citizen_rating IS NOT NULL
                           THEN citizen_rating END), 2)                    AS avg_rating
        FROM service_requests
        """
    ).fetchone()

    by_category = conn.execute(
        """
        SELECT category, COUNT(*) AS count
        FROM   service_requests
        GROUP  BY category
        ORDER  BY count DESC
        """
    ).fetchall()

    by_sub_county = conn.execute(
        """
        SELECT sub_county, COUNT(*) AS count
        FROM   service_requests
        GROUP  BY sub_county
        ORDER  BY count DESC
        """
    ).fetchall()

    audit_log_rows = conn.execute(
        """
        SELECT *
        FROM   audit_logs
        ORDER  BY id DESC
        LIMIT  25
        """
    ).fetchall()

    conn.close()

    return (
        jsonify(
            {
                "summary":      _row_to_dict(summary_row),
                "by_category":  [_row_to_dict(r) for r in by_category],
                "by_sub_county":[_row_to_dict(r) for r in by_sub_county],
                "audit_logs":   [_row_to_dict(r) for r in audit_log_rows],
            }
        ),
        200,
    )


# ---------------------------------------------------------------------------
# 7. GET /api/requests/export — admin CSV export (formula-injection safe)
# ---------------------------------------------------------------------------


@requests_bp.route("/requests/export", methods=["GET"])
@login_required
@admin_required
def export_csv(current_user: dict):
    """Export all service requests as a downloadable CSV file.

    CSV Formula Injection Defence (OWASP A03):
        Any cell value that starts with  =  +  -  @  (characters that Excel /
        LibreOffice Calc interpret as formula prefixes) is prefixed with a
        single-quote character ``'``.  This causes spreadsheet applications to
        treat the cell as plain text, preventing arbitrary formula execution
        when an admin opens the file.

    The CSV is generated in-memory (``io.StringIO``) and streamed via
    ``flask.Response`` rather than written to disk, avoiding temporary-file
    cleanup concerns.

    Returns:
        200 OK — CSV file download (Content-Disposition: attachment)
    """
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT sr.ticket_id, sr.category, sr.sub_county, sr.location,
               sr.priority, sr.assigned_unit, sr.status,
               sr.admin_remarks, sr.citizen_rating,
               u.full_name  AS citizen_name,
               u.email      AS citizen_email,
               u.phone      AS citizen_phone,
               sr.created_at, sr.updated_at
        FROM   service_requests sr
        LEFT JOIN users u ON u.id = sr.user_id
        ORDER  BY sr.id DESC
        """
    ).fetchall()
    conn.close()

    _FORMULA_CHARS = frozenset("=+-@")

    def _sanitize(value: str) -> str:
        """Prepend a quote to any cell that starts with a formula character."""
        s = str(value) if value is not None else ""
        if s and s[0] in _FORMULA_CHARS:
            return "'" + s
        return s

    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")

    # Header row
    writer.writerow(
        [
            "Ticket ID", "Category", "Sub-County", "Location",
            "Priority", "Assigned Unit", "Status",
            "Admin Remarks", "Citizen Rating",
            "Citizen Name", "Citizen Email", "Citizen Phone",
            "Submitted At", "Last Updated",
        ]
    )

    for row in rows:
        writer.writerow(
            [
                _sanitize(row["ticket_id"]),
                _sanitize(row["category"]),
                _sanitize(row["sub_county"]),
                _sanitize(row["location"]),
                _sanitize(row["priority"]),
                _sanitize(row["assigned_unit"]),
                _sanitize(row["status"]),
                _sanitize(row["admin_remarks"]),
                _sanitize(row["citizen_rating"]),
                _sanitize(row["citizen_name"]),
                _sanitize(row["citizen_email"]),
                _sanitize(row["citizen_phone"]),
                _sanitize(row["created_at"]),
                _sanitize(row["updated_at"]),
            ]
        )

    csv_bytes = output.getvalue().encode("utf-8-sig")   # BOM for Excel compat

    return Response(
        csv_bytes,
        status=200,
        mimetype="text/csv",
        headers={
            "Content-Disposition": (
                "attachment; filename=muranga_service_requests.csv"
            )
        },
    )


# ---------------------------------------------------------------------------
# 8a. GET /api/admin/users — list all users with request counts
# ---------------------------------------------------------------------------


@requests_bp.route("/admin/users", methods=["GET"])
@login_required
@admin_required
def list_users(current_user: dict):
    """Return all registered users with a count of their submitted requests.

    Uses a LEFT JOIN + COUNT so users with zero requests are still included.
    ``password_hash`` is excluded from the SELECT list — it must never travel
    outside the database layer, even to an admin endpoint.

    Returns:
        200 OK — { "users": [ { id, full_name, email, phone, sub_county,
                                 role, is_active, created_at,
                                 request_count }, … ] }
    """
    conn  = get_db_connection()
    rows  = conn.execute(
        """
        SELECT u.id, u.full_name, u.email, u.phone, u.sub_county,
               u.role, u.is_active, u.created_at,
               COUNT(sr.id) AS request_count
        FROM   users u
        LEFT JOIN service_requests sr ON sr.user_id = u.id
        GROUP  BY u.id
        ORDER  BY u.id
        """
    ).fetchall()
    conn.close()

    return jsonify({"users": [_row_to_dict(r) for r in rows]}), 200


# ---------------------------------------------------------------------------
# 8b. PATCH /api/admin/users/<user_id>/toggle-status — activate/deactivate
# ---------------------------------------------------------------------------


@requests_bp.route("/admin/users/<int:user_id>/toggle-status", methods=["PATCH"])
@login_required
@admin_required
def toggle_user_status(current_user: dict, user_id: int):
    """Activate or deactivate a user account (soft-delete pattern).

    Safety Guard:
        An admin cannot deactivate their own account through this endpoint.
        This prevents a situation where the sole admin accidentally locks
        themselves out, requiring direct database access to recover.

    Toggling sets is_active to the opposite of its current value:
        1 (active)   → 0 (deactivated)
        0 (deactivated) → 1 (active)

    The action is recorded in audit_logs for accountability.

    Args:
        user_id: Integer primary key of the user to toggle.

    Returns:
        200 OK          — { "message": "…", "is_active": 0|1 }
        400 Bad Request — admin trying to deactivate themselves
        404 Not Found   — no user with that ID
    """
    if user_id == current_user["id"]:
        return (
            jsonify(
                {
                    "error": (
                        "You cannot deactivate your own admin account. "
                        "Ask another admin to do so if necessary."
                    )
                }
            ),
            400,
        )

    conn    = get_db_connection()
    target  = conn.execute(
        "SELECT id, full_name, is_active, role FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    if not target:
        conn.close()
        return jsonify({"error": f"No user found with ID {user_id}."}), 404

    new_status = 0 if target["is_active"] == 1 else 1
    action_str = "activated" if new_status == 1 else "deactivated"
    now        = _now_iso()
    ip         = _get_ip()

    with conn:
        conn.execute(
            "UPDATE users SET is_active = ? WHERE id = ?",
            (new_status, user_id),
        )
        conn.execute(
            """
            INSERT INTO audit_logs
                (actor_name, actor_email, actor_role, ticket_id, action, ip_address, timestamp)
            VALUES (?, ?, 'admin', 'SYSTEM', ?, ?, ?)
            """,
            (
                current_user["full_name"],
                current_user.get("email") or session.get("email", ""),
                f"Admin {action_str} user account: {target['full_name']} "
                f"(ID: {user_id}, role: {target['role']})",
                ip,
                now,
            ),
        )

    conn.close()
    return (
        jsonify(
            {
                "message": (
                    f"User '{target['full_name']}' has been {action_str} successfully."
                ),
                "is_active": new_status,
            }
        ),
        200,
    )


# ---------------------------------------------------------------------------
# 9a. DELETE /api/requests/<int:req_id> — citizen dismisses a single resolved ticket
# ---------------------------------------------------------------------------


@requests_bp.route("/requests/<int:req_id>", methods=["DELETE"])
@login_required
def delete_single_request(current_user: dict, req_id: int):
    """Allow a citizen or admin to clear/delete a single addressed (Resolved) ticket.

    Ownership & Security Guard:
        - Admin can delete any ticket with status = 'Resolved'.
        - Citizen can only delete tickets where user_id = session["user_id"] AND status = 'Resolved'.
        - Unresolved (Pending / In Progress) tickets cannot be removed.
        - Deletion event with actor_email is recorded in audit_logs.

    Returns:
        200 OK — { "message": "Ticket MCG-... has been cleared." }
        400 Bad Request — ticket is not Resolved
        403 Forbidden — citizen does not own this ticket
        404 Not Found — ticket does not exist
    """
    conn = get_db_connection()
    row = conn.execute(
        "SELECT id, ticket_id, user_id, status FROM service_requests WHERE id = ?",
        (req_id,),
    ).fetchone()

    if not row:
        conn.close()
        return jsonify({"error": f"No service request found with ID {req_id}."}), 404

    is_admin = current_user.get("role") == "admin"

    # Ownership check
    if not is_admin and row["user_id"] != current_user["id"]:
        conn.close()
        return (
            jsonify({"error": "You do not have permission to delete this ticket."}),
            403,
        )

    # Resolution check (only resolved tickets may be cleared)
    if row["status"] != "Resolved":
        conn.close()
        return (
            jsonify(
                {
                    "error": (
                        "Only addressed/resolved tickets can be cleared. "
                        f"Current status is '{row['status']}'."
                    )
                }
            ),
            400,
        )

    ticket_id   = row["ticket_id"]
    now         = _now_iso()
    ip          = _get_ip()
    actor_name  = session.get("full_name") or current_user.get("full_name", "Officer")
    actor_email = session.get("email") or current_user.get("email", "")
    actor_role  = current_user.get("role", "citizen")

    with conn:
        conn.execute("DELETE FROM service_requests WHERE id = ?", (req_id,))
        conn.execute(
            """
            INSERT INTO audit_logs
                (actor_name, actor_email, actor_role, ticket_id, action, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                actor_name,
                actor_email,
                actor_role,
                ticket_id,
                f"{'Admin' if is_admin else 'Citizen'} cleared resolved service ticket {ticket_id}",
                ip,
                now,
            ),
        )

    conn.close()
    return (
        jsonify(
            {
                "message": f"Resolved ticket {ticket_id} has been cleared.",
                "deleted_id": req_id,
                "ticket_id": ticket_id,
            }
        ),
        200,
    )


# ---------------------------------------------------------------------------
# 9b. DELETE /api/requests/clear-resolved — citizen or admin clears resolved tickets
# ---------------------------------------------------------------------------


@requests_bp.route("/requests/clear-resolved", methods=["DELETE"])
@login_required
def clear_all_resolved_requests(current_user: dict):
    """Delete all 'Resolved' tickets (scoped to citizen or county-wide for admin).

    Ownership & Security Guard:
        - If role == 'admin': deletes all tickets in service_requests where status = 'Resolved'.
        - If role == 'citizen': deletes only tickets where user_id = session["user_id"] AND status = 'Resolved'.
        - Unresolved tickets remain intact.
        - Deletion event with count and actor_email is written to audit_logs.

    Returns:
        200 OK — { "message": "...", "cleared_count": N }
    """
    is_admin = current_user.get("role") == "admin"
    user_id  = current_user["id"]
    conn     = get_db_connection()

    if is_admin:
        resolved_rows = conn.execute(
            "SELECT id, ticket_id FROM service_requests WHERE status = 'Resolved'"
        ).fetchall()
    else:
        resolved_rows = conn.execute(
            "SELECT id, ticket_id FROM service_requests WHERE user_id = ? AND status = 'Resolved'",
            (user_id,),
        ).fetchall()

    cleared_count = len(resolved_rows)
    if cleared_count == 0:
        conn.close()
        return jsonify({"message": "No addressed/resolved tickets to clear.", "cleared_count": 0}), 200

    now         = _now_iso()
    ip          = _get_ip()
    actor_name  = session.get("full_name") or current_user.get("full_name", "Officer")
    actor_email = session.get("email") or current_user.get("email", "")
    actor_role  = current_user.get("role", "citizen")

    ticket_ids_str = ", ".join([r["ticket_id"] for r in resolved_rows[:5]])
    if cleared_count > 5:
        ticket_ids_str += f" and {cleared_count - 5} more"

    with conn:
        if is_admin:
            conn.execute("DELETE FROM service_requests WHERE status = 'Resolved'")
        else:
            conn.execute(
                "DELETE FROM service_requests WHERE user_id = ? AND status = 'Resolved'",
                (user_id,),
            )

        conn.execute(
            """
            INSERT INTO audit_logs
                (actor_name, actor_email, actor_role, ticket_id, action, ip_address, timestamp)
            VALUES (?, ?, ?, 'BATCH', ?, ?, ?)
            """,
            (
                actor_name,
                actor_email,
                actor_role,
                f"{'Admin' if is_admin else 'Citizen'} cleared {cleared_count} addressed tickets ({ticket_ids_str})",
                ip,
                now,
            ),
        )

    conn.close()
    return (
        jsonify(
            {
                "message": f"Successfully cleared {cleared_count} addressed service request(s).",
                "cleared_count": cleared_count,
            }
        ),
        200,
    )

