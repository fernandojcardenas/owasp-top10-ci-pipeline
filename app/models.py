import os
import sqlite3

from werkzeug.security import check_password_hash, generate_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "notes.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()

def create_user(username, password):
    conn = get_db()
    # FIX (A02:2021 Cryptographic Failures): the password is hashed with werkzeug's salted
    # PBKDF2 hash before it ever touches the database, so the database (and any backup or leak
    # of it) never holds a recoverable password. See docs/vulnerabilities/02-plaintext-passwords.md.
    password_hash = generate_password_hash(password)
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password_hash))
    conn.commit()
    conn.close()

def find_user_by_username(username):
    conn = get_db()
    # FIX (A03:2021 Injection - SQL Injection): the query uses a parameterized placeholder
    # instead of string interpolation, so user input can never change the shape of the SQL
    # statement. See docs/vulnerabilities/03-sql-injection-login.md.
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row

def verify_credentials(username, password):
    user = find_user_by_username(username)
    if user is None:
        # Run a dummy hash check even when the username doesn't exist, so the response time
        # doesn't reveal whether a username is registered (a basic timing-safe pattern).
        check_password_hash(generate_password_hash("dummy"), password)
        return None
    if not check_password_hash(user["password"], password):
        return None
    return user

def get_user_by_id(user_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row

def create_note(owner_id, title, content):
    conn = get_db()
    conn.execute(
        "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)",
        (owner_id, title, content),
    )
    conn.commit()
    conn.close()

def get_notes_for_user(owner_id):
    conn = get_db()
    rows = conn.execute("SELECT * FROM notes WHERE owner_id = ?", (owner_id,)).fetchall()
    conn.close()
    return rows

def get_note_for_owner(note_id, owner_id):
    conn = get_db()
    # FIX (A01:2021 Broken Access Control - IDOR): the lookup is scoped to the requesting
    # user's own notes, so a user can no longer read another user's note just by guessing or
    # incrementing the id in the URL. See docs/vulnerabilities/01-idor-note-access.md.
    row = conn.execute(
        "SELECT * FROM notes WHERE id = ? AND owner_id = ?", (note_id, owner_id)
    ).fetchone()
    conn.close()
    return row
