import os
import secrets

from flask import Flask

def create_app():
    app = Flask(__name__)

    # FIX (A05:2021 Security Misconfiguration): the secret key now comes from an environment
    # variable, so it is never committed to source control. If the variable is unset (e.g. in a
    # quick local run) we fall back to a random key generated at process start; sessions won't
    # survive a restart in that case, which is an acceptable tradeoff for never shipping a
    # hardcoded key that would be identical, and public, in every deployment.
    # See docs/vulnerabilities/05-hardcoded-secret-and-debug-mode.md.
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    from . import config_loader

    app.config["APP_SETTINGS"] = config_loader.load_config()

    from . import models

    models.init_db()

    from .routes import bp

    app.register_blueprint(bp)

    @app.after_request
    def set_security_headers(response):
        # FIX: caught by the DAST stage (OWASP ZAP baseline scan), not by SAST or SCA, which
        # is exactly the kind of gap a live scan of the running app finds and a source-code
        # scanner can't. See docs/ci-pipeline.md.
        response.headers["X-Frame-Options"] = "DENY"  # ZAP 10020: Missing Anti-clickjacking Header
        response.headers["X-Content-Type-Options"] = "nosniff"  # ZAP 10021
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"  # ZAP 90004
        response.headers["Server"] = "Werkzeug"  # ZAP 10036: don't leak the exact version
        return response

    return app
