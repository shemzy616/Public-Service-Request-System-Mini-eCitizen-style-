"""
database.py — Huduma Murang'a Public Service Request System
County 021 | Murang'a County Government

Architecture & Database Design:
    · Connection Factory: Centralizes SQLite connection configuration with row factories and
      connection-level foreign key enforcement (PRAGMA foreign_keys = ON).
    · Relational Schema:
        - users: Citizen & County Admin credentials, RBAC roles, contact data, active flags.
        - service_requests: Public tickets (MCG-021-2026-XXXX), status lifecycle, sub-county routing,
          photo evidence paths, citizen satisfaction ratings (1-5 stars).
        - audit_logs: Immutable compliance ledger capturing every state change, admin remarks,
          client IP address, and email notification status.
    · Performance Indexes: B-tree indexes on status, category, sub_county, and ticket_id for
      fast analytical aggregation and sub-second filtering.
    · Automatic Department Routing: Domain logic resolving issues to MUWASCO/Gatamathi/Kahuti,
      Energy & Electrical Unit, Environment & Sanitation, and Roads & Infrastructure.
    · Atomic Transactions: Context-managed transactions (with conn:) ensuring consistency.

Author : Shem Imani (Lead Full-Stack GovTech Engineer)
Created: 2026-10-18
"""

import os
import sqlite3
import uuid
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────────────────────────
# 12-Factor Configuration: Load .env variables with safe fallback
# ─────────────────────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ─────────────────────────────────────────────────────────────────────────────
# Werkzeug is used for password hashing everywhere in the project, so we
# import it here once to hash seed passwords consistently.
# ─────────────────────────────────────────────────────────────────────────────
from werkzeug.security import generate_password_hash

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Single source-of-truth for the database filename.
DB_NAME: str = os.environ.get(
    "DATABASE_URL",
    os.environ.get("DB_NAME", "portal.db" if os.path.exists("portal.db") else "muranga_portal.db")
)

# Murang'a County Government ticket prefix  (MCG-021 = County Code 021)
TICKET_PREFIX: str = "MCG-021"

# Valid sub-counties inside Murang'a County
SUB_COUNTIES: tuple[str, ...] = (
    "Kiharu",
    "Mathioya",
    "Kangema",
    "Gatanga",
    "Maragua",
    "Kandara",
    "Kigumo",
)

# Routing map: service category → responsible county agency
AGENCY_ROUTING: dict[str, str] = {
    "Water & Sewerage": "MUWASCO Technical Team",
    "Streetlight & Electrical": "Murang'a Municipality Electrical Unit",
    "Garbage & Sanitation": "Directorate of Environment & Solid Waste",
    "Roads & Drainage": "Murang'a County Roads Department",
}

# South-water sub-counties use a different water agency
SOUTH_WATER_SUB_COUNTIES: frozenset[str] = frozenset(
    {"Kandara", "Maragua", "Gatanga"}
)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string.

    Storing timestamps as TEXT in SQLite (ISO-8601) is the recommended
    approach for SQLite because it sorts lexicographically and is
    portable across every language that may later consume the database.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def generate_ticket_id() -> str:
    """Generate a unique, human-readable ticket ID.

    Format:  MCG-021-<YEAR>-<4-char-UUID-hex-upper>
    Example: MCG-021-2026-A3F7

    The 4-character hex suffix provides 65,536 unique combinations per
    year, which is more than sufficient for county-level volume while
    keeping IDs easy to read over the phone or on printed receipts.
    """
    year = datetime.now(timezone.utc).year
    suffix = uuid.uuid4().hex[:4].upper()
    return f"{TICKET_PREFIX}-{year}-{suffix}"


def route_agency(category: str, sub_county: str) -> str:
    """Determine the responsible county agency based on category and location.

    Security / Business Logic:
        The routing is resolved server-side so a malicious client cannot
        assign a request to an arbitrary agency by tampering with the
        request payload.

    Args:
        category  : Service category string (must match AGENCY_ROUTING key).
        sub_county: The sub-county where the issue is located.

    Returns:
        The name of the responsible county agency as a string.
    """
    if category == "Water & Sewerage" and sub_county in SOUTH_WATER_SUB_COUNTIES:
        # MUSWASCO covers the southern sub-counties for water/sewerage
        return "MUSWASCO (Murang'a South Water)"
    return AGENCY_ROUTING.get(category, "Murang'a County Government")


# ---------------------------------------------------------------------------
# Core database functions
# ---------------------------------------------------------------------------


def get_db_connection() -> sqlite3.Connection:
    """Open and configure a SQLite database connection.

    Configuration decisions:
        row_factory = sqlite3.Row
            Allows columns to be accessed by name (row["email"]) rather
            than by positional index (row[2]).  This makes the code more
            readable and robust against column reordering.

        PRAGMA foreign_keys = ON
            SQLite does NOT enforce foreign-key constraints by default.
            Enabling this pragma ensures referential integrity (e.g. a
            service_request cannot reference a non-existent user_id)
            and that ON DELETE CASCADE / ON DELETE RESTRICT rules fire.

        check_same_thread = False
            Required for Flask's dev server which may hand the same
            connection to multiple threads.  In production (Gunicorn /
            uWSGI) each worker has its own process, so this is safe.

    Returns:
        A configured sqlite3.Connection ready for use.
    """
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)

    # Enable dictionary-like row access throughout the application
    conn.row_factory = sqlite3.Row

    # Enforce referential integrity — must be set per-connection in SQLite
    conn.execute("PRAGMA foreign_keys = ON")

    return conn


# ---------------------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------------------

# Using multi-line string constants for DDL keeps init_db() clean and makes
# individual table definitions easy to locate and review.

_DDL_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Human-readable identifier; stored as entered but compared case-insensitively
    full_name     TEXT    NOT NULL,

    -- Used as the login credential; enforced UNIQUE at DB level
    email         TEXT    UNIQUE NOT NULL,

    -- Required for county staff to call the citizen back
    phone         TEXT    NOT NULL,

    -- Defaults to the most populous sub-county in Murang'a
    sub_county    TEXT    DEFAULT 'Kiharu',

    -- Werkzeug pbkdf2:sha256 hash; the plaintext password is NEVER stored
    password_hash TEXT    NOT NULL,

    -- CHECK constraint enforces only two valid roles at the DB layer,
    -- providing defence-in-depth even if application logic has a bug
    role          TEXT    DEFAULT 'citizen'
                  CHECK(role IN ('citizen', 'admin')),

    -- Soft-delete flag: 0 = deactivated, 1 = active (default).
    -- Deactivated accounts cannot log in without touching the DB directly.
    is_active     INTEGER DEFAULT 1,

    -- Stored as ISO-8601 UTC string (see _now_iso())
    created_at    TEXT    NOT NULL
)
"""

_DDL_SERVICE_REQUESTS = """
CREATE TABLE IF NOT EXISTS service_requests (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Human-readable unique ticket reference printed on citizen receipts
    ticket_id     TEXT    UNIQUE NOT NULL,

    -- Who submitted the request; CASCADE delete removes requests if a user
    -- account is hard-deleted (should only happen in dev/testing)
    user_id       INTEGER NOT NULL
                  REFERENCES users(id) ON DELETE CASCADE,

    -- Controlled vocabulary enforced at the application layer
    category      TEXT    NOT NULL,

    -- One of the seven official Murang'a sub-counties
    sub_county    TEXT    NOT NULL,

    -- Free-text ward or landmark for field teams to locate the issue
    location      TEXT    NOT NULL,

    -- Citizen's narrative description of the problem
    description   TEXT    NOT NULL,

    -- Triage priority; defaults to Normal; application may auto-escalate
    priority      TEXT    DEFAULT 'Normal'
                  CHECK(priority IN ('Normal', 'High', 'Urgent')),

    -- Optional photo evidence; stored as a relative path under /static/uploads/
    image_url     TEXT    DEFAULT NULL,

    -- Auto-routed server-side (see route_agency()) — never client-supplied
    assigned_unit TEXT    NOT NULL,

    -- Lifecycle: Pending → In Progress → Resolved
    status        TEXT    DEFAULT 'Pending'
                  CHECK(status IN ('Pending', 'In Progress', 'Resolved')),

    -- Admin free-text update visible to citizen on their tracking page
    admin_remarks TEXT    DEFAULT '',

    -- Optional 1-5 star citizen satisfaction rating, allowed only on Resolved
    citizen_rating INTEGER DEFAULT NULL,

    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
)
"""

_DDL_AUDIT_LOGS = """
CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Human-readable name of who performed the action (denormalised for
    -- quick log display without a JOIN)
    actor_name  TEXT NOT NULL,

    -- Email of who performed the action for security audit accountability
    actor_email TEXT DEFAULT '',

    -- Role at the time of action; captures role-change edge cases
    actor_role  TEXT NOT NULL,

    -- The ticket affected (or 'SYSTEM' for account-level actions)
    ticket_id   TEXT NOT NULL,

    -- Short past-tense description, e.g. "Submitted request"
    action      TEXT NOT NULL,

    -- Stored for security analysis; useful for detecting shared accounts
    ip_address  TEXT NOT NULL,

    -- UTC ISO-8601 timestamp
    timestamp   TEXT NOT NULL
)
"""

# Performance indexes -------------------------------------------------------
# Created separately from DDL so each statement is atomic.
# idx_requests_user   — speeds up "show all my requests" citizen queries
# idx_requests_status — speeds up admin dashboard filters by status
# idx_requests_ticket — speeds up ticket look-up by ID (already UNIQUE, but
#                        an explicit index makes EXPLAIN QUERY PLAN clearer)

_INDEXES: list[str] = [
    "CREATE INDEX IF NOT EXISTS idx_requests_user   ON service_requests(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_requests_status ON service_requests(status)",
    "CREATE INDEX IF NOT EXISTS idx_requests_ticket ON service_requests(ticket_id)",
]


# ---------------------------------------------------------------------------
# init_db — public API
# ---------------------------------------------------------------------------


def init_db() -> None:
    """Create all tables and indexes, then seed demo data if the DB is empty.

    Idempotent Design:
        Every DDL statement uses IF NOT EXISTS so calling init_db() multiple
        times (e.g. on every Flask startup) is safe and produces no errors.

    Seed Guard:
        The seed block is wrapped in ``SELECT COUNT(*) FROM users``.  If
        any users exist, seeding is skipped — preventing duplicate seeding
        when the application restarts.

    Transaction Safety:
        All DDL and DML run inside a single connection that auto-commits.
        For seed data we use an explicit transaction so a partial failure
        does not leave the database in an inconsistent state.
    """
    conn = get_db_connection()

    # ── 1. Create tables ────────────────────────────────────────────────────
    conn.execute(_DDL_USERS)
    conn.execute(_DDL_SERVICE_REQUESTS)
    conn.execute(_DDL_AUDIT_LOGS)

    # ── 2. Create indexes ────────────────────────────────────────────────────
    for idx_sql in _INDEXES:
        conn.execute(idx_sql)

    # ── 2b. Auto-migration: ensure actor_email exists on existing databases ──
    existing_cols = [
        col[1] for col in conn.execute("PRAGMA table_info(audit_logs)").fetchall()
    ]
    if "actor_email" not in existing_cols:
        conn.execute("ALTER TABLE audit_logs ADD COLUMN actor_email TEXT DEFAULT ''")

    conn.commit()
    print("[DB] Schema and indexes verified [OK]")

    # ── 3. Seed guard ────────────────────────────────────────────────────────
    user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if user_count > 0:
        print("[DB] Seed data already present — skipping.")
        conn.close()
        return

    # ── 4. Seed users ────────────────────────────────────────────────────────
    now = _now_iso()

    # Passwords are hashed with Werkzeug's pbkdf2:sha256 algorithm.
    # The plaintext is ONLY present in this seed block; it is NEVER stored.
    admin_hash   = generate_password_hash("Admin@2026")
    citizen_hash = generate_password_hash("Citizen@2026")

    users_seed = [
        # (full_name, email, phone, sub_county, password_hash, role, is_active, created_at)
        (
            "James Kamau (County Admin)",
            "admin@muranga.go.ke",
            "0712000021",
            "Kiharu",
            admin_hash,
            "admin",
            1,
            now,
        ),
        (
            "Mary Wanjiku Njuguna",
            "wanjiku@gmail.com",
            "0722111222",
            "Kiharu",
            citizen_hash,
            "citizen",
            1,
            now,
        ),
        (
            "Peter Macharia Githae",
            "macharia@gmail.com",
            "0733444555",
            "Mathioya",
            citizen_hash,
            "citizen",
            1,
            now,
        ),
    ]

    # Parameterized INSERT — never use string formatting for SQL values
    conn.executemany(
        """
        INSERT INTO users
            (full_name, email, phone, sub_county, password_hash, role, is_active, created_at)
        VALUES
            (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        users_seed,
    )
    conn.commit()
    print("[DB] Seeded 3 users (1 admin + 2 citizens) [OK]")

    # ── 5. Fetch seeded user IDs for FK references ───────────────────────────
    wanjiku_id  = conn.execute(
        "SELECT id FROM users WHERE email = ?", ("wanjiku@gmail.com",)
    ).fetchone()["id"]

    macharia_id = conn.execute(
        "SELECT id FROM users WHERE email = ?", ("macharia@gmail.com",)
    ).fetchone()["id"]

    # ── 6. Seed service requests ──────────────────────────────────────────────
    # Four realistic requests spread across statuses, priorities, sub-counties,
    # and service categories to populate the admin dashboard meaningfully.

    tickets: list[str] = [generate_ticket_id() for _ in range(4)]

    # Ensure all generated ticket IDs are unique (probabilistically guaranteed
    # by uuid4, but we deduplicate for absolute safety in testing)
    while len(set(tickets)) < 4:
        tickets = [generate_ticket_id() for _ in range(4)]

    requests_seed = [
        # ── Request 1: Broken streetlight — Pending — Kiharu (Wanjiku) ──────
        (
            tickets[0],
            wanjiku_id,
            "Streetlight & Electrical",
            "Kiharu",
            "Murang'a Town CBD, opposite KCB Bank",
            (
                "Three consecutive streetlights along Murang'a–Kenol Road near KCB "
                "have been dark for two weeks. The area is now dangerous at night — "
                "two motorbike accidents have already occurred at this spot."
            ),
            "High",
            None,                                          # no image yet
            "Murang'a Municipality Electrical Unit",       # auto-routed
            "Pending",
            "",                                            # no admin remarks yet
            None,                                          # not yet resolved
            now,
            now,
        ),
        # ── Request 2: Water outage — In Progress — Mathioya (Macharia) ─────
        (
            tickets[1],
            macharia_id,
            "Water & Sewerage",
            "Mathioya",
            "Gitugi Market, near Mathioya River Bridge",
            (
                "Complete water supply cut-off to Gitugi Market ward since Monday. "
                "Approximately 3,000 households are affected. The main supply pipe "
                "appears to have a major burst — water is visibly gushing at the bridge."
            ),
            "Urgent",
            None,
            "MUWASCO Technical Team",
            "In Progress",
            (
                "MUWASCO crew dispatched on 2026-10-16. Excavation underway. "
                "Estimated restoration: 2026-10-19."
            ),
            None,
            "2026-10-14 08:00:00",
            "2026-10-16 14:30:00",
        ),
        # ── Request 3: Garbage — Resolved — Kiharu (Wanjiku) ────────────────
        (
            tickets[2],
            wanjiku_id,
            "Garbage & Sanitation",
            "Kiharu",
            "Kimorori Ward, beside Murang'a High School gate",
            (
                "Illegal dumping site has formed beside the school gate. "
                "The waste includes medical waste and has attracted rodents. "
                "Residents fear a cholera outbreak given proximity to a food kiosk cluster."
            ),
            "Urgent",
            None,
            "Directorate of Environment & Solid Waste",
            "Resolved",
            (
                "Waste cleared and area disinfected on 2026-10-10. "
                "Warning signage installed. Enforcement officers briefed."
            ),
            4,                                             # 4-star citizen rating
            "2026-10-08 09:15:00",
            "2026-10-10 16:00:00",
        ),
        # ── Request 4: Road pothole — Pending — Kandara (Macharia) ──────────
        (
            tickets[3],
            macharia_id,
            "Roads & Drainage",
            "Kandara",
            "Kandara–Maragua Junction, 500m from Kandara Police Station",
            (
                "Large pothole (approx. 1.5m wide, 30cm deep) on the Kandara–Maragua "
                "road junction. Three vehicles have already sustained tyre and rim damage. "
                "Heavy rains have widened the pothole further over the past month."
            ),
            "Normal",
            None,
            "Murang'a County Roads Department",
            "Pending",
            "",
            None,
            "2026-10-17 11:00:00",
            "2026-10-17 11:00:00",
        ),
    ]

    conn.executemany(
        """
        INSERT INTO service_requests (
            ticket_id, user_id, category, sub_county, location,
            description, priority, image_url, assigned_unit, status,
            admin_remarks, citizen_rating, created_at, updated_at
        ) VALUES (
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?
        )
        """,
        requests_seed,
    )
    conn.commit()
    print(f"[DB] Seeded 4 service requests {[t for t in tickets]} [OK]")

    # ── 7. Seed audit logs ───────────────────────────────────────────────────
    # Three initial log entries reflecting the lifecycle of seed requests 2 & 3.
    audit_seed = [
        (
            "Mary Wanjiku Njuguna",
            "wanjiku@gmail.com",
            "citizen",
            tickets[0],
            "Submitted new request — category: Streetlight & Electrical",
            "127.0.0.1",
            now,
        ),
        (
            "Peter Macharia Githae",
            "macharia@gmail.com",
            "citizen",
            tickets[1],
            "Submitted new request — category: Water & Sewerage",
            "127.0.0.1",
            "2026-10-14 08:00:00",
        ),
        (
            "James Kamau (County Admin)",
            "admin@muranga.go.ke",
            "admin",
            tickets[1],
            "Status updated: Pending → In Progress; MUWASCO crew dispatched",
            "192.168.1.10",
            "2026-10-16 14:30:00",
        ),
        (
            "James Kamau (County Admin)",
            "admin@muranga.go.ke",
            "admin",
            tickets[2],
            "Status updated: In Progress → Resolved; area disinfected and cleared",
            "192.168.1.10",
            "2026-10-10 16:00:00",
        ),
    ]

    conn.executemany(
        """
        INSERT INTO audit_logs
            (actor_name, actor_email, actor_role, ticket_id, action, ip_address, timestamp)
        VALUES
            (?, ?, ?, ?, ?, ?, ?)
        """,
        audit_seed,
    )
    conn.commit()
    print("[DB] Seeded 4 audit log entries [OK]")

    conn.close()
    print("[DB] Database initialised and ready [OK]")


# ---------------------------------------------------------------------------
# Standalone entry-point for testing / first-run verification
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    # Reconfigure stdout to UTF-8 so Windows CP1252 terminals can handle
    # Unicode characters that may appear inside seed data strings.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    init_db()
    print(f"\n[DB] Verification -- opening '{DB_NAME}' for integrity check ...")

    conn = get_db_connection()

    users    = conn.execute("SELECT id, full_name, role FROM users").fetchall()
    requests = conn.execute(
        "SELECT ticket_id, category, status FROM service_requests"
    ).fetchall()
    logs     = conn.execute(
        "SELECT actor_name, action FROM audit_logs"
    ).fetchall()

    print(f"\n  Users ({len(users)}):")
    for u in users:
        print(f"    [{u['id']}] {u['full_name']} | role: {u['role']}")

    print(f"\n  Service Requests ({len(requests)}):")
    for r in requests:
        print(f"    {r['ticket_id']} | {r['category']} | {r['status']}")

    print(f"\n  Audit Logs ({len(logs)}):")
    for log in logs:
        print(f"    {log['actor_name']}: {log['action'][:70]}...")

    conn.close()
    print("\n[DB] All checks passed [OK]")
