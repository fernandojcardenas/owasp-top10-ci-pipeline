import os

from werkzeug.serving import WSGIRequestHandler

from app import create_app

app = create_app()


class QuietRequestHandler(WSGIRequestHandler):
    # FIX (A06/ZAP 10036 Server Leaks Version Information): Werkzeug's dev server adds its own
    # "Server" header at the socket level, ignoring whatever the app sets in the response, so
    # the app-level header override in app/__init__.py isn't enough on its own. Overriding
    # version_string() here is what actually stops the interpreter and Werkzeug version from
    # being broadcast on every response.
    def version_string(self):
        return "Werkzeug"


if __name__ == "__main__":
    # FIX (A05:2021 Security Misconfiguration): debug mode is now off unless FLASK_DEBUG=1 is
    # explicitly set. This keeps the interactive Werkzeug debugger (arbitrary code execution on
    # any unhandled exception) from ever being exposed by default.
    # See docs/vulnerabilities/05-hardcoded-secret-and-debug-mode.md.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", request_handler=QuietRequestHandler)
