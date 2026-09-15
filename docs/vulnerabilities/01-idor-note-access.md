# IDOR on note access

**OWASP category:** A01:2021 Broken Access Control
**CWE:** CWE-639 Authorization Bypass Through User-Controlled Key
**Location:** `app/models.py` (`get_note_by_id`), `app/routes.py` (`note_view`)

## The vulnerability

`GET /notes/<note_id>` looked a note up by its id alone and rendered it to whoever was
logged in, without checking that the note belonged to that user. Note ids are small
sequential integers, so any authenticated user could read any other user's notes just by
changing the number in the URL.

```python
def get_note_by_id(note_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    conn.close()
    return row
```

## Exploit

1. User `alice` registers, logs in, and creates a note titled "Secret" (becomes note id 1).
2. User `bob` registers and logs in with his own account, no relationship to alice.
3. Bob requests `alice`'s note directly by id.

```
$ curl -c bob.txt -b bob.txt -d "username=bob&password=bobpw" http://127.0.0.1:5000/register
$ curl -c bob.txt -b bob.txt -d "username=bob&password=bobpw" http://127.0.0.1:5000/login
$ curl -c bob.txt -b bob.txt http://127.0.0.1:5000/notes/1
<h1>Secret</h1>
<div>alice-only-note</div>
```

Bob, who has never interacted with alice's account, reads her note in full.

## Fix

The lookup now takes the requesting user's id and scopes the query to it:

```python
def get_note_for_owner(note_id, owner_id):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM notes WHERE id = ? AND owner_id = ?", (note_id, owner_id)
    ).fetchone()
    conn.close()
    return row
```

`note_view` passes `current_user()["id"]` in, so a note that exists but belongs to someone
else now returns the same "Note not found" response as a note that doesn't exist at all,
which also avoids leaking which ids are in use.

## Verification

Repeating the exact same steps on the hardened branch:

```
$ curl -c bob.txt -b bob.txt http://127.0.0.1:5000/notes/1
Note not found
```

HTTP status changed from `200` to `404`, and bob never sees alice's content.
