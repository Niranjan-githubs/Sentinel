"""Structured logging, run artifacts, and observation synthesis (plan §3d, §9).

The observation synthesizer compresses a raw HTTP response into a small,
prompt-safe object containing status, content delta, error keywords, and a
payload-reflection flag. This is what the model sees in its history window —
NOT the raw response body.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

import structlog

from agent.schemas import Observation, ToolResult


def configure_logging(level: int = logging.INFO) -> None:
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


class RunArtifacts:
    """Per-run artifacts directory: log.jsonl + screenshots/."""

    def __init__(
        self,
        base_dir: str | Path = "artifacts/runs",
        run_id: str | None = None,
    ):
        self.run_id = run_id or f"{int(time.time())}-{uuid.uuid4().hex[:6]}"
        self.dir = Path(base_dir) / self.run_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.shots_dir = self.dir / "screenshots"
        self.shots_dir.mkdir(exist_ok=True)
        self.log_path = self.dir / "log.jsonl"
        self._fh = open(self.log_path, "a", encoding="utf-8")

    def log(self, **fields: Any) -> None:
        fields.setdefault("ts", time.time())
        self._fh.write(json.dumps(fields, default=str, ensure_ascii=False) + "\n")
        self._fh.flush()

    def shot_path(self, iteration: int) -> str:
        return str(self.shots_dir / f"iter_{iteration:04d}.png")

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:  # noqa: BLE001
            pass


# Detection bank for cheap response analysis.
SQL_ERROR_KEYWORDS = (
    "SQLSTATE",
    "SQLITE_ERROR",
    "syntax error",
    "unclosed quotation",
    "unterminated quoted string",
    "ORA-",
    "Microsoft OLE DB",
    "PG::SyntaxError",
    "MySQL server",
    "Warning: mysql",
    "ODBC SQL",
    "near \"",
)
INFO_LEAK_KEYWORDS = (
    "Traceback",
    "stack trace",
    "/var/",
    "/home/",
    "C:\\",
)


def synthesize_observation(
    result: ToolResult,
    payload: str | None = None,
    previous_body_len: int = 0,
) -> Observation:
    body = result.raw_body_excerpt or ""
    body_l = body.lower()

    found: list[str] = []
    for kw in SQL_ERROR_KEYWORDS:
        if kw.lower() in body_l:
            found.append(kw)
    for kw in INFO_LEAK_KEYWORDS:
        if kw.lower() in body_l:
            found.append(kw)

    payload_reflected = bool(payload) and payload in body
    body_size = len(body)
    return Observation(
        status=result.status,
        ok=result.ok,
        body_size=body_size,
        content_delta=body_size - previous_body_len,
        error_keywords=found[:5],
        payload_reflected=payload_reflected,
        new_cookies=list(result.new_cookies),
        note=(result.error or "")[:200],
    )
