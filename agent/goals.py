"""Top-level goal predicates (plan §8).

Each predicate is a pure function ``(state, last_result) -> bool``. Returns True
when the run can terminate as success.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable

from agent.schemas import ToolResult
from agent.state import AgentState

GoalPredicate = Callable[[AgentState, ToolResult], bool]

# Sensitive-data fingerprints for DATA_EXFILTRATED checks.
_SENSITIVE_PATTERNS = [
    re.compile(r"admin@juice-sh\.op", re.IGNORECASE),
    re.compile(r"\bMD5\(", re.IGNORECASE),
    re.compile(r"\bSQLITE_(?:ERROR|MASTER)", re.IGNORECASE),
    re.compile(r"\$2[aby]\$\d{2}\$"),
]


_JWT_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_\-]+$")


def _is_valid_jwt(token: str) -> bool:
    """Return True only if *token* looks like a real signed JWT.

    Juice Shop issues HS256 JWTs on successful login. A valid JWT has exactly
    three dot-separated base64url segments and the header must decode to a JSON
    object containing an 'alg' key. This prevents false positives from any
    random cookie that happens to be named 'token'.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return False
    if not all(_JWT_SEGMENT_RE.match(p) for p in parts if p):
        return False
    try:
        # Pad to a multiple of 4 for standard base64 decoding.
        header_b64 = parts[0] + "==" [: (4 - len(parts[0]) % 4) % 4]
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        return isinstance(header, dict) and "alg" in header
    except Exception:  # noqa: BLE001
        return False


def juice_shop_authenticated(state: AgentState, last: ToolResult) -> bool:
    token = state.cookies.get("token", "")
    if token and _is_valid_jwt(token):
        state.authenticated = True
        return True
    body = (last.body_summary or "").lower()
    if "whoami" in body and '"id"' in body:
        state.authenticated = True
        return True
    return False


def juice_shop_data_exfiltrated(state: AgentState, last: ToolResult) -> bool:
    body = last.raw_body_excerpt or last.body_summary or ""
    return any(p.search(body) for p in _SENSITIVE_PATTERNS)



def dvwa_authenticated(state: AgentState, last: ToolResult) -> bool:
    """Return True when DVWA login bypass is confirmed.

    Victory condition 1 — LOGGED IN:
    DVWA sets a ``security`` cookie ONLY after successful login.
    We also check for the Logout link in the body (present on every
    post-login page) but NOT on login.php itself.
    """
    # Primary signal: security-level cookie (low/medium/high/impossible)
    if state.cookies.get("security"):
        state.authenticated = True
        return True
    # Secondary signal: body has Logout + Welcome — NOT on the login page
    body = (last.raw_body_excerpt or last.body_summary or "").lower()
    url = (last.url or state.current_url or "").lower()
    if "login.php" not in url and "logout" in body and ("welcome" in body or "dvwa" in body):
        state.authenticated = True
        return True
    return False


# DVWA data-exfiltration fingerprints — fire on the SQLi results page
_DVWA_EXFIL_PATTERNS = [
    re.compile(r"First name:", re.IGNORECASE),   # SQLi results row header
    re.compile(r"Surname:", re.IGNORECASE),       # SQLi results row header
    re.compile(r"UNION SELECT", re.IGNORECASE),   # reflected in error output
    re.compile(r"information_schema", re.IGNORECASE),  # DB meta-data leak
    re.compile(r"root@", re.IGNORECASE),           # MySQL user leak
]


def dvwa_sqli_success(state: AgentState, last: ToolResult) -> bool:
    """Victory condition 2 — DATA EXFILTRATED from /vulnerabilities/sqli/."""
    body = last.raw_body_excerpt or last.body_summary or ""
    # Must have BOTH First name and Surname — prevents false positives
    return bool(re.search(r"First name:", body, re.IGNORECASE)) and \
           bool(re.search(r"Surname:", body, re.IGNORECASE))


def dvwa_pwned(state: AgentState, last: ToolResult) -> bool:
    """Combined DVWA victory: fires on EITHER login bypass OR data exfiltration.

    Phase 1 — Login bypass via SQLi on /login.php → security cookie set.
    Phase 2 — Data exfiltration via SQLi on /vulnerabilities/sqli/ →
               user rows returned (First name / Surname present in body).

    Whichever fires first wins. The agent doesn't need to do both.
    """
    if dvwa_authenticated(state, last):
        state.goal_detail = "logged_in"
        return True
    if dvwa_sqli_success(state, last):
        state.goal_detail = "data_exfiltrated"
        return True
    return False


_REGISTRY: dict[str, GoalPredicate] = {
    "AUTHENTICATED": juice_shop_authenticated,
    "DATA_EXFILTRATED": juice_shop_data_exfiltrated,
    "DVWA_SQLI_SUCCESS": dvwa_sqli_success,
    "DVWA_AUTHENTICATED": dvwa_authenticated,
    "DVWA_PWNED": dvwa_pwned,           # ← combined goal: login bypass OR exfil
}


def get(name: str) -> GoalPredicate:
    if name not in _REGISTRY:
        raise KeyError(f"unknown goal: {name!r}; known: {sorted(_REGISTRY)}")
    return _REGISTRY[name]
