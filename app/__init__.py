from flask import Flask

# VULN (A05:2021 Security Misconfiguration): a hardcoded secret key committed to source control.
# In a real deployment this must come from an environment variable or secrets manager instead.
SECRET_KEY = "dev-secret-do-not-use-in-prod-12345"

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = SECRET_KEY

    from . import config_loader

    app.config["APP_SETTINGS"] = config_loader.load_config()

    from . import models

    models.init_db()

    from .routes import bp

    app.register_blueprint(bp)

    return app
