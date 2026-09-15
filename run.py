from app import create_app

app = create_app()

if __name__ == "__main__":
    # VULN (A05:2021 Security Misconfiguration): debug mode must never be enabled in production.
    # It exposes the Werkzeug interactive debugger, which allows arbitrary code execution to
    # anyone who can trigger an unhandled exception in the running app.
    app.run(debug=True)
