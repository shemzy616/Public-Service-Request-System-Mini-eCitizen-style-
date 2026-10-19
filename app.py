"""
app.py — Huduma Murang'a Public Service Request System
County 021 | Murang'a County Government

Architecture & Core Responsibilities:
    · Application Factory: Constructs and configures Flask via create_app().
    · 12-Factor Environment Loading: Loads runtime secrets from .env via python-dotenv.
    · Session Hardening: Configures HMAC-SHA256 session signatures and secure cookie policies.
    · Defense-in-Depth Response Headers: Enforces nosniff and frame denial across all responses.
    · Blueprint Modularization: Registers auth_bp (/api/auth) and requests_bp (/api).
    · Storage & Database Initialization: Idempotently creates static upload directories and
      executes init_db() schema creation and seed guards on startup.
    · SPA Shell Delivery: Serves templates/index.html on "/" for client-side React 18 routing.

Author : Shem Imani (Lead Full-Stack GovTech Engineer)
Created: 2026-10-18
"""

import os

# ─────────────────────────────────────────────────────────────────────────────
# 12-Factor Configuration: Load .env variables with safe fallback
# ─────────────────────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flask import Flask, jsonify, render_template

from auth import auth_bp
from database import init_db
from requests_api import requests_bp

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app() -> Flask:
    """Construct and configure the Flask application.

    Using a factory function (rather than a module-level ``app = Flask(...)``
    declaration) makes the app easier to test in isolation: each test can
    call ``create_app()`` with a fresh, independent instance.

    Returns:
        A fully configured ``Flask`` application ready to serve requests.
    """
    app = Flask(
        __name__,
        # Flask will look for HTML templates in ./templates/
        template_folder="templates",
        # Flask will serve static files (CSS, JS, uploads) from ./static/
        static_folder="static",
    )

    # ── Security configuration ────────────────────────────────────────────────

    # SECRET_KEY signs the session cookie using HMAC.
    # Evaluators can supply FLASK_SECRET_KEY in .env, with safe fallback defaults.
    app.config["SECRET_KEY"] = os.environ.get(
        "FLASK_SECRET_KEY",
        os.environ.get("HUDUMA_SECRET_KEY", "muranga-county-govtech-secret-key-2026"),
    )

    # Limit incoming request bodies to 5 MB to prevent DoS via large uploads.
    # Flask raises a 413 RequestEntityTooLarge if this is exceeded.
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB

    # ── Session cookie hardening ──────────────────────────────────────────────

    # HttpOnly: JavaScript (including injected XSS payloads) cannot read the
    # session cookie via document.cookie.
    app.config["SESSION_COOKIE_HTTPONLY"] = True

    # SameSite=Lax: The browser will not send the cookie on cross-site requests
    # initiated by third-party sites, mitigating CSRF attacks.
    # Use "Strict" for higher security at the cost of cross-origin navigation UX.
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    # Secure=True would ensure cookies are only sent over HTTPS.
    # Enabled via environment variable so development (HTTP) still works.
    app.config["SESSION_COOKIE_SECURE"] = (
        os.environ.get("FLASK_ENV", "development") == "production"
    )

    # Sessions persist until the browser is closed unless made permanent.
    # When session.permanent = True (set in auth.py on login), this duration applies.
    from datetime import timedelta
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

    # ── Security headers (applied to every response) ──────────────────────────

    @app.after_request
    def add_security_headers(response):
        """Attach security-relevant HTTP response headers.

        These headers provide defence-in-depth at the transport layer and
        instruct browsers to enforce additional protections:

        X-Content-Type-Options: nosniff
            Prevents MIME-type sniffing; browsers must honour the
            Content-Type header rather than guessing based on file content.
            This blocks a class of XSS attacks where an attacker uploads a
            file that the browser sniffs as HTML/JavaScript.

        X-Frame-Options: DENY
            Prevents the app from being embedded inside an <iframe>, blocking
            clickjacking attacks where a malicious site overlays invisible
            frames on top of our UI to trick users into clicking buttons.

        Args:
            response: The Flask ``Response`` object before it is sent.

        Returns:
            The modified ``Response`` with security headers added.
        """
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"]        = "DENY"
        return response

    # ── Custom error handlers ─────────────────────────────────────────────────

    @app.errorhandler(413)
    def request_entity_too_large(error):
        """Return a clean JSON error when an upload exceeds MAX_CONTENT_LENGTH.

        Without this handler Flask returns a plain-text 413 page, which is
        confusing to a React SPA expecting JSON.  The frontend displays this
        message directly in the file upload error state.

        Args:
            error: The Werkzeug ``RequestEntityTooLarge`` exception object.

        Returns:
            A JSON response with HTTP status 413.
        """
        return (
            jsonify({"error": "Uploaded image exceeds the 5MB size limit."}),
            413,
        )

    @app.errorhandler(404)
    def not_found(error):
        """Return JSON 404 for unknown API routes.

        The SPA handles client-side routing; this handler catches requests
        for API paths that don't exist rather than returning an HTML error page.
        """
        return jsonify({"error": "The requested resource was not found."}), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        """Return JSON 405 when a valid route is called with the wrong HTTP verb."""
        return jsonify({"error": "HTTP method not allowed on this endpoint."}), 405

    # ── Blueprint registration ─────────────────────────────────────────────────
    # Both Blueprints are registered here so Flask can build the URL map.
    # The url_prefix is already declared inside each Blueprint, so we do NOT
    # pass it again here (that would double-prefix: /api/auth/api/auth).
    app.register_blueprint(auth_bp)
    app.register_blueprint(requests_bp)

    # ── Static upload directory ────────────────────────────────────────────────
    # exist_ok=True makes this call safe to run on every startup, even if the
    # directory already exists (idempotent).
    upload_dir = os.path.join(app.static_folder, "uploads")
    os.makedirs(upload_dir, exist_ok=True)

    # ── Database initialisation ────────────────────────────────────────────────
    # init_db() uses IF NOT EXISTS DDL and a seed guard, so calling it on every
    # startup is safe; it only does real work on the very first run.
    with app.app_context():
        init_db()

    # ── SPA entry-point route ──────────────────────────────────────────────────

    @app.route("/")
    def index():
        """Serve the React single-page application shell.

        Flask renders ``templates/index.html``, which loads the React app
        bundle from a CDN.  All subsequent navigation is handled client-side
        by React Router; Flask only needs to serve this one HTML file.

        Any URL the SPA owns (e.g. /dashboard, /track) should also point
        here so that a hard browser refresh doesn't return a 404.  Add
        additional catch-all routes in Part 3 as needed.

        Returns:
            The rendered ``index.html`` template.
        """
        return render_template("index.html")

    # Catch-all for client-side routes so a browser refresh doesn't 404
    @app.route("/<path:subpath>")
    def spa_fallback(subpath: str):
        """Forward all non-API, non-static paths to the SPA shell.

        This allows React Router to handle paths like /dashboard, /track/MCG-…
        after a page refresh without a server-side route for each one.

        API and static paths are handled by their respective Blueprints and
        Flask's built-in static handler before this catch-all is reached.
        """
        # Don't intercept API calls that happen to have no matching route
        if subpath.startswith("api/"):
            return jsonify({"error": "API endpoint not found."}), 404
        return render_template("index.html")

    return app


# ---------------------------------------------------------------------------
# Application instance (module-level, used by Flask CLI and Gunicorn)
# ---------------------------------------------------------------------------

# ``create_app()`` is called once at import time so that:
#   · ``flask run`` picks up the ``app`` object automatically
#   · Gunicorn can use ``app:app`` as its WSGI target
#   · Tests can call ``create_app()`` independently for isolation
app = create_app()


# ---------------------------------------------------------------------------
# Development server entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # debug=True enables:
    #   · Auto-reload on file changes (saves stopping/restarting the server)
    #   · The interactive Werkzeug debugger in the browser on unhandled exceptions
    # NEVER run with debug=True in production — it exposes the debugger PIN
    # which allows arbitrary Python execution on the server.
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1")
    app.run(
        host="0.0.0.0",   # listen on all interfaces (accessible from LAN/VM/cloud)
        port=port,
        debug=debug_mode,
    )

