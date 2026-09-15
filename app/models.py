import os
import sqlite3

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
    # VULN (A02:2021 Cryptographic Failures): the password is stored in plaintext. It should be
    # hashed (e.g. werkzeug.security.generate_password_hash) before it ever touches the database.
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()

def find_user_by_credentials(username, password):
    conn = get_db()
    # VULN (A03:2021 Injection - SQL Injection): the query is built with an f-string instead of
    # parameterized placeholders. A username of `' OR '1'='1` bypasses authentication entirely.
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    row = conn.execute(query).fetchone()
    conn.close()
    return row

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

def get_note_by_id(note_id):
    conn = get_db()
    # VULN (A01:2021 Broken Access Control - IDOR): this lookup never checks that the requesting
    # user owns the note, so any authenticated user can read any other user's note just by
    # guessing or incrementing the id in the URL.
    row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    conn.close()
    return row
