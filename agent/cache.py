"""Caches.

Per plan §6:
  - DOM cache: hash(url + raw_html) -> pruned DOM string. In-memory LRU. Per-run.
  - Outcome cache: (url, method, param, payload_hash) -> outcome row in sqlite.
    Persisted across runs so identical attacks aren't re-executed.

Prefix KV cache lives at the model server (vLLM --enable-prefix-caching) — not
managed here; the agent simply guarantees that the system prompt is byte-stable.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from collections import OrderedDict
from pathlib import Path


def _hash(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


class DomCache:
    """Thread-safe LRU cache of pruned DOM strings keyed by (url, raw_html) hash."""

    def __init__(self, capacity: int = 256):
        self._cap = max(1, capacity)
        self._store: OrderedDict[str, str] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, url: str, raw_html: str) -> str | None:
        key = _hash(url, raw_html)
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
                return self._store[key]
        return None

    def put(self, url: str, raw_html: str, pruned: str) -> None:
        key = _hash(url, raw_html)
        with self._lock:
            self._store[key] = pruned
            self._store.move_to_end(key)
            while len(self._store) > self._cap:
                self._store.popitem(last=False)


class OutcomeCache:
    """SQLite-backed cache of payload outcomes; survives across runs."""

    def __init__(self, db_path: str | Path):
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS outcomes (
                    key TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    method TEXT NOT NULL,
                    param TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    status INTEGER NOT NULL,
                    ok INTEGER NOT NULL,
                    body_summary TEXT NOT NULL DEFAULT '',
                    payload_reflected INTEGER NOT NULL DEFAULT 0,
                    error_keywords TEXT NOT NULL DEFAULT '[]',
                    ts REAL NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._db_path, timeout=5.0)
        c.execute("PRAGMA journal_mode=WAL")
        return c

    @staticmethod
    def _key(url: str, method: str, param: str, payload: str) -> str:
        return _hash(url, method, param, payload)

    def get(self, url: str, method: str, param: str, payload: str) -> dict | None:
        key = self._key(url, method, param, payload)
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT status, ok, body_summary, payload_reflected, error_keywords "
                "FROM outcomes WHERE key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        return {
            "status": int(row[0]),
            "ok": bool(row[1]),
            "body_summary": row[2] or "",
            "payload_reflected": bool(row[3]),
            "error_keywords": json.loads(row[4] or "[]"),
        }

    def put(
        self,
        url: str,
        method: str,
        param: str,
        payload: str,
        *,
        status: int,
        ok: bool,
        body_summary: str,
        payload_reflected: bool,
        error_keywords: list[str],
    ) -> None:
        key = self._key(url, method, param, payload)
        payload_hash = _hash(payload)
        with self._lock, self._connect() as conn:
            conn.execute(
                "REPLACE INTO outcomes(key,url,method,param,payload_hash,status,ok,"
                "body_summary,payload_reflected,error_keywords,ts) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    key, url, method, param, payload_hash,
                    int(status), int(ok), body_summary or "",
                    int(payload_reflected), json.dumps(error_keywords or []),
                    time.time(),
                ),
            )
