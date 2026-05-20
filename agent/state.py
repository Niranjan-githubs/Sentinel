"""Mutable run-time agent state.

Tracks visited URLs, attempted (url, param, payload) tuples, current cookies,
findings, and a sliding window of recent (turn, observation) pairs.
"""

from __future__ import annotations

import hashlib
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque

from agent.schemas import ModelTurn, Observation


def attempt_key(url: str, param: str, payload: str) -> str:
    h = hashlib.sha256(f"{url}\x00{param}\x00{payload}".encode()).hexdigest()
    return h[:16]


@dataclass
class AgentState:
    base_url: str
    goal: str
    history_capacity: int = 5
    current_url: str = ""
    authenticated: bool = False
    role: str = "anon"
    cookies: dict[str, str] = field(default_factory=dict)
    visited_urls: set[str] = field(default_factory=set)
    attempted: set[str] = field(default_factory=set)
    unique_payloads: set[str] = field(default_factory=set)
    history: Deque[tuple[ModelTurn, Observation]] = field(default_factory=deque)
    iteration: int = 0
    model_calls: int = 0
    started_at: float = field(default_factory=time.time)
    findings: list[dict] = field(default_factory=list)
    last_action_status: str = "n/a"
    url_attempt_counts: dict[str, int] = field(default_factory=dict)
    consecutive_no_progress: int = 0
    consecutive_stop_actions: int = 0  # counts unconfirmed STOP turns in a row
    consecutive_connection_failures: int = 0  # mid-run Ollama drop detection
    goal_detail: str = ""  # set by goal predicate, e.g. "logged_in" or "data_exfiltrated"

    def __post_init__(self) -> None:
        if self.history.maxlen != self.history_capacity:
            self.history = deque(self.history, maxlen=self.history_capacity)

    def record_turn(self, turn: ModelTurn, obs: Observation) -> None:
        self.history.append((turn, obs))

    def mark_attempt(self, url: str, param: str, payload: str) -> None:
        self.attempted.add(attempt_key(url, param, payload))
        self.unique_payloads.add(payload)
        self.url_attempt_counts[url] = self.url_attempt_counts.get(url, 0) + 1

    def already_attempted(self, url: str, param: str, payload: str) -> bool:
        return attempt_key(url, param, payload) in self.attempted

    def visit(self, url: str) -> None:
        self.visited_urls.add(url)
        self.current_url = url

    def attempts_against(self, url: str) -> int:
        return self.url_attempt_counts.get(url, 0)

    def elapsed_seconds(self) -> float:
        return time.time() - self.started_at
