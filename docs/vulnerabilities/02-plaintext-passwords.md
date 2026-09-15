# Plaintext password storage

**OWASP category:** A02:2021 Cryptographic Failures
**CWE:** CWE-256 Plaintext Storage of a Password
**Location:** `app/models.py` (`create_user`)

## The vulnerability

Registration wrote the password the user typed straight into the `users` table with no
hashing at all:

```python
def create_user(username, password):
    conn = get_db()
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()
```

Anyone who can read the database file, either directly, through a backup, or through a
different vulnerability (like the SQL injection in this same app), recovers every user's
actual password, not just a hash of it. Since people reuse passwords across sites, this
kind of leak has consequences well beyond this one app.

## Exploit

Register a user, then read the database file directly, no vulnerability needed beyond
having read access to `notes.db`:

```
$ curl -d "username=alice&password=alicepw" http://127.0.0.1:5000/register
$ python3 -c "
import sqlite3
conn = sqlite3.connect('notes.db')
conn.row_factory = sqlite3.Row
for row in conn.execute('SELECT username, password FROM users'):
    print(dict(row))
"
{'username': 'alice', 'password': 'alicepw'}
```

The password is sitting there in the clear.

## Fix

Registration now hashes the password with Werkzeug's `generate_password_hash` (salted
PBKDF2-SHA256), and login checks it with `check_password_hash` instead of comparing raw
strings:

```python
def create_user(username, password):
    conn = get_db()
    password_hash = generate_password_hash(password)
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password_hash))
    conn.commit()
    conn.close()
```

The database never holds anything the original password can be recovered from.

## Verification

```
$ python3 -c "
import sqlite3
conn = sqlite3.connect('notes.db')
conn.row_factory = sqlite3.Row
for row in conn.execute('SELECT username, password FROM users WHERE username=\"alice\"'):
    print(dict(row))
"
{'username': 'alice', 'password': 'pbkdf2:sha256:260000$dwfnANUaqtDOVpKg$c4acf14b67e555917809e20d96b3c8a34c3495cafe93b2375b2a88fd0a836bc2'}
```

Login still works normally for the correct password (verified through the app's own
register/login flow), but the stored value is now a salted hash.
