"""Local persistent storage (policy, baseline, scan history). Everything stays on disk, offline."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path

from .platform_utils import IS_MAC, IS_WIN


def data_dir() -> Path:
    if os.environ.get("SENTINEL_DATA"):
        d = Path(os.environ["SENTINEL_DATA"])
    elif IS_WIN:
        d = Path(os.environ.get("APPDATA", Path.home())) / "Sentinel"
    elif IS_MAC:
        d = Path.home() / "Library" / "Application Support" / "Sentinel"
    else:
        d = Path.home() / ".sentinel"
    d.mkdir(parents=True, exist_ok=True)
    return d


DEFAULT_POLICY = {
    "mode": "monitor",              # monitor = flag only threats/anomalies; allowlist = anything not allowed is unauthorised
    "learning_hours": 24,           # baseline learning window for anomaly detection
    "allowed_ips": [],
    "allowed_domains": [],
    "blocked_ips": [],
    "blocked_domains": [],
    "fw_blocked_ports": [],         # "TCP/445" - firewall rules Sentinel created (port still listens, but is unreachable)
    "fw_blocked_ips": [],           # IPs Sentinel blocked in the firewall
    "applied_fixes": {},            # finding id -> time a fix succeeded (cleared once the check passes)
    "trusted_apps": [],             # process names never flagged by anomaly detection
    "ollama_model": "llama3.2",
    "ollama_url": "http://127.0.0.1:11434",
}

_lock = threading.Lock()


def load_policy() -> dict:
    f = data_dir() / "policy.json"
    pol = dict(DEFAULT_POLICY)
    if f.exists():
        try:
            pol.update(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            pass
    return pol


def save_policy(pol: dict) -> dict:
    merged = load_policy()
    for k, v in pol.items():
        if k in DEFAULT_POLICY:
            merged[k] = v
    (data_dir() / "policy.json").write_text(json.dumps(merged, indent=2), encoding="utf-8")
    return merged


def db() -> sqlite3.Connection:
    con = sqlite3.connect(data_dir() / "sentinel.db", timeout=10, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""CREATE TABLE IF NOT EXISTS seen (
        app TEXT, dest TEXT, port INTEGER, first_seen REAL, last_seen REAL, hits INTEGER,
        PRIMARY KEY (app, dest, port))""")
    con.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
    con.execute("""CREATE TABLE IF NOT EXISTS events (
        ts REAL, kind TEXT, severity TEXT, title TEXT, detail TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS actions (
        ts REAL, action TEXT, target TEXT, ok INTEGER, output TEXT)""")
    return con


def meta_get(k: str, default=None):
    with _lock:
        con = db()
        row = con.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        con.close()
    return row[0] if row else default


def meta_set(k: str, v: str) -> None:
    with _lock:
        con = db()
        con.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (k, v))
        con.commit()
        con.close()


def install_time() -> float:
    t = meta_get("install_time")
    if t is None:
        t = str(time.time())
        meta_set("install_time", t)
    return float(t)


def log_event(kind: str, severity: str, title: str, detail: str = "") -> None:
    with _lock:
        con = db()
        con.execute("INSERT INTO events VALUES (?,?,?,?,?)", (time.time(), kind, severity, title, detail[:2000]))
        con.execute("DELETE FROM events WHERE ts < ?", (time.time() - 30 * 86400,))
        con.commit()
        con.close()


def log_action(action: str, target: str, ok: bool, output: str) -> None:
    with _lock:
        con = db()
        con.execute("INSERT INTO actions VALUES (?,?,?,?,?)", (time.time(), action, target, int(ok), output[:4000]))
        con.commit()
        con.close()


def recent(table: str, limit: int = 200) -> list[dict]:
    assert table in ("events", "actions")
    with _lock:
        con = db()
        con.row_factory = sqlite3.Row
        rows = [dict(r) for r in con.execute(f"SELECT * FROM {table} ORDER BY ts DESC LIMIT ?", (limit,))]
        con.close()
    return rows
