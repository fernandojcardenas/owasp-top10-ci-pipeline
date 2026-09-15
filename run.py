import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # FIX (A05:2021 Security Misconfiguration): debug mode is now off unless FLASK_DEBUG=1 is
    # explicitly set. This keeps the interactive Werkzeug debugger (arbitrary code execution on
    # any unhandled exception) from ever being exposed by default.
    # See docs/vulnerabilities/05-hardcoded-secret-and-debug-mode.md.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
