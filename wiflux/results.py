"""SQLite-backed result storage with JSON export."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import CrackResult


class ResultStore:
    def __init__(self, data_dir: str):
        self.db_path = Path(data_dir) / "wiflux.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cracks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bssid TEXT NOT NULL,
                    essid TEXT,
                    key TEXT NOT NULL,
                    method TEXT NOT NULL,
                    capture_file TEXT,
                    cracked_at TEXT NOT NULL,
                    UNIQUE(bssid, method)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ignored (
                    bssid TEXT PRIMARY KEY,
                    essid TEXT,
                    reason TEXT,
                    ignored_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    interface TEXT,
                    targets_found INTEGER,
                    targets_attacked INTEGER,
                    cracks INTEGER
                )
            """)

    def save_crack(self, result: CrackResult) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO cracks
                   (bssid, essid, key, method, capture_file, cracked_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (result.bssid, result.essid, result.key, result.method,
                 result.capture_file, result.cracked_at or now),
            )

    def is_cracked(self, bssid: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM cracks WHERE bssid = ?", (bssid,)
            ).fetchone()
        return row is not None

    def get_cracked_bssids(self) -> set[str]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("SELECT bssid FROM cracks").fetchall()
        return {r[0] for r in rows}

    def ignore(self, bssid: str, essid: str, reason: str = "user") -> None:
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO ignored VALUES (?, ?, ?, ?)",
                (bssid, essid, reason, now),
            )

    def list_ignored(self) -> list[tuple[str, str, str, str]]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT bssid, essid, reason, ignored_at FROM ignored ORDER BY ignored_at DESC"
            ).fetchall()
        return [(r[0], r[1] or "", r[2] or "", r[3] or "") for r in rows]

    def list_cracks(self) -> list[CrackResult]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT bssid, essid, key, method, capture_file, cracked_at FROM cracks"
            ).fetchall()
        return [
            CrackResult(bssid=r[0], essid=r[1] or "", key=r[2], method=r[3],
                        capture_file=r[4] or "", cracked_at=r[5])
            for r in rows
        ]

    def export_json(self, path: str) -> None:
        data = {
            "cracks": [
                {
                    "bssid": c.bssid, "essid": c.essid, "key": c.key,
                    "method": c.method, "capture_file": c.capture_file,
                    "cracked_at": c.cracked_at,
                }
                for c in self.list_cracks()
            ]
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def start_session(self, interface: str) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO sessions (started_at, interface, targets_found, targets_attacked, cracks) VALUES (?, ?, 0, 0, 0)",
                (now, interface),
            )
            return cur.lastrowid

    def update_session(self, session_id: int, **kwargs) -> None:
        allowed = {"targets_found", "targets_attacked", "cracks"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                f"UPDATE sessions SET {set_clause} WHERE id = ?",
                (*updates.values(), session_id),
            )