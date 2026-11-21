"""SQLite storage for scans and findings."""
import json
import os
import sqlite3
from datetime import datetime

from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    mode TEXT,
    progress INTEGER DEFAULT 0,
    message TEXT,
    duration_s REAL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    title TEXT, source TEXT, url TEXT, owasp TEXT, cwe INTEGER, param TEXT,
    evidence TEXT, description TEXT, severity TEXT, risk_score INTEGER,
    confidence TEXT, remediation TEXT, extra TEXT
);
"""


def _conn():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    return c


def create_scan(target, mode):
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO scans (target, started_at, status, mode, progress, message) VALUES (?,?,?,?,0,?)",
            (target, datetime.now().isoformat(timespec="seconds"), "running", mode, "Starting"),
        )
        return cur.lastrowid


def update_progress(scan_id, progress, message):
    with _conn() as c:
        c.execute("UPDATE scans SET progress=?, message=? WHERE id=?", (progress, message, scan_id))


def finish_scan(scan_id, status, message, duration_s):
    with _conn() as c:
        c.execute(
            "UPDATE scans SET status=?, message=?, progress=100, finished_at=?, duration_s=? WHERE id=?",
            (status, message, datetime.now().isoformat(timespec="seconds"), duration_s, scan_id),
        )


def save_findings(scan_id, findings):
    with _conn() as c:
        c.executemany(
            "INSERT INTO findings (scan_id,title,source,url,owasp,cwe,param,evidence,description,"
            "severity,risk_score,confidence,remediation,extra) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [(scan_id, f.title, f.source, f.url, f.owasp, f.cwe, f.param, f.evidence, f.description,
              f.severity, f.risk_score, f.confidence, f.remediation, json.dumps(f.extra)) for f in findings],
        )


def list_scans():
    with _conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM scans ORDER BY id DESC")]


def get_scan(scan_id):
    with _conn() as c:
        r = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(r) if r else None


def get_findings(scan_id):
    with _conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY risk_score DESC", (scan_id,))]
