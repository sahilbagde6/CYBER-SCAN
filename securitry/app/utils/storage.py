"""
SQLite storage layer.
Handles both scan history and user accounts.
"""

import sqlite3
import json
import logging
from datetime import datetime

log = logging.getLogger(__name__)


# ── Database initialisation ────────────────────────────────────────────────

def init_db(db_path: str) -> None:
    """Create all tables if they don't already exist."""
    con = sqlite3.connect(db_path)
    cur = con.cursor()

    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT    NOT NULL UNIQUE,
            email      TEXT    NOT NULL UNIQUE,
            password   TEXT    NOT NULL,
            created_at TEXT    NOT NULL
        )
    """)

    # Scans table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            created_at  TEXT    NOT NULL,
            target_url  TEXT    NOT NULL,
            hostname    TEXT    NOT NULL,
            risk_score  INTEGER NOT NULL,
            risk_level  TEXT    NOT NULL,
            result_json TEXT    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    con.commit()
    con.close()
    log.info("Database initialised at %s", db_path)


# ── User helpers ───────────────────────────────────────────────────────────

def create_user(db_path: str, username: str, email: str, password_hash: str) -> int:
    """Insert a new user. Returns the new user ID."""
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username, email, password, created_at) VALUES (?, ?, ?, ?)",
        (username.strip(), email.strip().lower(), password_hash,
         datetime.utcnow().isoformat() + "Z"),
    )
    user_id = cur.lastrowid
    con.commit()
    con.close()
    log.info("New user created: %s (id=%s)", username, user_id)
    return user_id


def get_user_by_email(db_path: str, email: str) -> dict | None:
    """Return a user dict by email, or None if not found."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),))
    row = cur.fetchone()
    con.close()
    return dict(row) if row else None


def get_user_by_id(db_path: str, user_id: int) -> dict | None:
    """Return a user dict by ID, or None if not found."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    con.close()
    return dict(row) if row else None


def email_exists(db_path: str, email: str) -> bool:
    """Return True if the email is already registered."""
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("SELECT 1 FROM users WHERE email = ?", (email.strip().lower(),))
    exists = cur.fetchone() is not None
    con.close()
    return exists


def username_exists(db_path: str, username: str) -> bool:
    """Return True if the username is already taken."""
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ?", (username.strip(),))
    exists = cur.fetchone() is not None
    con.close()
    return exists


# ── Scan helpers ───────────────────────────────────────────────────────────

def insert_scan(db_path: str, result: dict, user_id: int | None = None) -> None:
    """Store a completed scan result."""
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("""
        INSERT INTO scans
            (user_id, created_at, target_url, hostname, risk_score, risk_level, result_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        datetime.utcnow().isoformat() + "Z",
        result["target"]["url"],
        result["target"]["hostname"],
        int(result["risk"]["score"]),
        result["risk"]["level"],
        json.dumps(result),
    ))
    con.commit()
    con.close()


def list_scans(db_path: str, limit: int = 20, user_id: int | None = None) -> list:
    """Return summary rows, optionally filtered to a specific user."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    if user_id is not None:
        cur.execute("""
            SELECT id, created_at, target_url, hostname, risk_score, risk_level
            FROM scans WHERE user_id = ?
            ORDER BY id DESC LIMIT ?
        """, (user_id, limit))
    else:
        cur.execute("""
            SELECT id, created_at, target_url, hostname, risk_score, risk_level
            FROM scans ORDER BY id DESC LIMIT ?
        """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return rows


def get_scan_by_id(db_path: str, scan_id: int) -> dict | None:
    """Return a full scan result dict by ID."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cur.fetchone()
    con.close()
    if not row:
        return None
    d = dict(row)
    d["result"] = json.loads(d["result_json"])
    return d
