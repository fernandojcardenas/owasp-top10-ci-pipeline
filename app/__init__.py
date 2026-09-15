import os
import secrets

from flask import Flask
from flask_wtf import CSRFProtect

csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)

    # FIX (A05:2021 Security Misconfiguration): the secret key now comes from an environment
    # variable, so it is never committed to source control. If the variable is unset (e.g. in a
    # quick local run) we fall back to a random key generated at process start; sessions won't
    # survive a restart in that case, which is an acceptable tradeoff for never shipping a
    # hardcoded key that would be identical, and public, in every deployment.
    # See docs/vulnerabilities/05-hardcoded-secret-and-debug-mode.md.
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    # FIX (ZAP 10202 Absence of Anti-CSRF Tokens): every POST form now requires a valid,
    # per-session CSRF token (see the templates), or Flask-WTF rejects the request with a 400.
    csrf.init_app(app)

    # FIX (ZAP 10054 Cookie without SameSite Attribute): the session cookie is only sent on
    # same-site requests, which blocks it from being attached to a cross-site form submission
    # or link in the first place.
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    from . import config_loader

    app.config["APP_SETTINGS"] = config_loader.load_config()

    from . import models

    models.init_db()

    from .routes import bp

    app.register_blueprint(bp)

    @app.after_request
    def set_security_headers(response):
        # FIX: every header below was caught by the DAST stage (OWASP ZAP baseline scan
        # against the actually-running app), not by SAST or SCA, which is exactly the kind of
        # gap a live scan finds and a source-code scanner can't. See docs/ci-pipeline.md.
        response.headers["X-Frame-Options"] = "DENY"  # ZAP 10020
        response.headers["X-Content-Type-Options"] = "nosniff"  # ZAP 10021
        # ZAP 10038 + 10055: frame-ancestors, object-src, and base-uri don't fall back to
        # default-src per the CSP spec, so they're listed explicitly rather than assumed.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["Permissions-Policy"] = (
            "geolocation=(), camera=(), microphone=()"
        )  # ZAP 10063
        # ZAP 90004 (Insufficient Site Isolation Against Spectre) checks for all three of these.
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"  # this app is all private, per-user data
        response.headers["Server"] = "Werkzeug"  # ZAP 10036: don't leak the exact version
        return response

    return app
