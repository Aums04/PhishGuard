"""SQLite-backed assessment history. Stores domain + hash, not the full raw URL."""
import sqlite3
import hashlib
import os
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "phishguard.db")


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                domain TEXT NOT NULL,
                url_hash TEXT NOT NULL,
                rule_score INTEGER NOT NULL,
                rule_verdict TEXT NOT NULL,
                ml_probability REAL NOT NULL,
                ml_label TEXT NOT NULL,
                final_verdict TEXT NOT NULL
            )
        """)


def save_assessment(domain: str, raw_url: str, rule_result: dict, ml_result: dict, final_verdict: str) -> int:
    url_hash = hashlib.sha256(raw_url.encode()).hexdigest()[:16]
    with _conn() as conn:
        cur = conn.execute(
            """INSERT INTO assessments
               (timestamp, domain, url_hash, rule_score, rule_verdict,
                ml_probability, ml_label, final_verdict)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                domain,
                url_hash,
                rule_result["score"],
                rule_result["verdict"],
                ml_result["phishing_probability"],
                ml_result["label"],
                final_verdict,
            ),
        )
        return cur.lastrowid


def get_history(limit: int = 200):
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM assessments ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_assessment(assessment_id: int):
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM assessments WHERE id = ?", (assessment_id,)
        ).fetchone()
        return dict(row) if row else None
