"""SENTINEL <-> agent bridge.

The fine-tuned model speaks the SENTINEL schema (from `dataset/convert_to_llama3.py`):
  System prompt: verbatim SENTINEL prompt
  User format:   GOAL / HTML_SNIPPET / PRIOR_TURNS
  Output:        single JSON object {Thought, Action, Action_Input}
  Action vocab:  SQL_INJECT, XSS_INJECT, RETRY_MUTATED, ANALYZE_RESPONSE,
                 CRAWL_DEEPER, WAIT, STOP

The agent's tool layer (agent/schemas.py) speaks a different vocab
(NAVIGATE, INJECT_PAYLOAD, SUBMIT_FORM, REPORT_FINDING, ...).

This module translates both directions:
  parse_sentinel_output(raw) -> ModelTurn      (model -> agent)
  build_sentinel_user_prompt(...) -> str       (agent state -> model user msg)

History rendering reverse-maps agent Actions back to SENTINEL dicts so the
PRIOR_TURNS section the model sees matches the format it was trained on.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Any

from pydantic import ValidationError

from agent.schemas import (
    Action,
    CrawlDeeper,
    HttpMethod,
    InjectPayload,
    ModelTurn,
    Navigate,
    Observation,
    ReportFinding,
    SubmitForm,
    VulnClass,
    Wait,
)


# Verbatim from dataset/convert_to_llama3.py:24 — must match training-time bytes.
SENTINEL_SYSTEM_PROMPT = """You are SENTINEL, an autonomous web-exploitation agent. Given an HTML snippet and a goal (and optionally prior agent turns), you reason about vulnerabilities and emit a single JSON action that advances the exploit loop:

observe -> identify attack surface -> select exploit -> generate payload -> interpret response -> adapt and retry -> detect success -> STOP

Prioritize vulnerability sinks: form action, input value, src, href, hidden fields, query parameters, JSON body fields, and reflected DOM contexts. Infer the backend from HTML evidence (.php, .aspx, __VIEWSTATE, .jsp, /rest/, <app-*>, wp-content, etc.) and choose context-appropriate payloads.

Output a single JSON object with exactly these keys:
- Thought: <=4 sentences, <=80 words; cite the specific sink, backend inference, injection context, and payload-class justification (or signal classification for ANALYZE_RESPONSE / success indicator for STOP).
- Action: one of SQL_INJECT | XSS_INJECT | RETRY_MUTATED | ANALYZE_RESPONSE | CRAWL_DEEPER | WAIT | STOP.
- Action_Input: object with target_url, method, parameters, headers, rationale, plus action-specific fields (mutation_class for RETRY_MUTATED; signal + next_recommended for ANALYZE_RESPONSE; success_state + evidence for STOP).

Output ONLY the JSON. No prose, no markdown fences, no commentary."""


VALID_SENTINEL_ACTIONS = frozenset({
    "SQL_INJECT", "XSS_INJECT", "RETRY_MUTATED",
    "ANALYZE_RESPONSE", "CRAWL_DEEPER", "WAIT", "STOP",
})


class SentinelParseError(ValueError):
    """Raised when SENTINEL model output cannot be parsed or mapped to an Action."""


# ─── public API ────────────────────────────────────────────────────────────────

def build_sentinel_user_prompt(
    *,
    goal: str,
    base_url: str,
    current_url: str,
    pruned_dom: str,
    history: Sequence[tuple[ModelTurn, Observation]],
    extra_hint: str = "",
) -> str:
    """Build the user message in the exact format the model was SFT'd on.

    Layout (matching dataset/convert_to_llama3.py):
        GOAL: <goal>

        HTML_SNIPPET:
        <pruned dom>

        PRIOR_TURNS (N):

        --- Turn 1 ---
        Thought: ...
        Action: ...
        Action_Input: {...}
        Observation: ...

        --- Turn 2 ---
        ...
    """
    parts: list[str] = [f"GOAL: {goal}"]

    if pruned_dom and pruned_dom.strip():
        parts.append(f"HTML_SNIPPET:\n{pruned_dom}")
    else:
        parts.append("HTML_SNIPPET: (empty — see prior_turns for context)")

    if history:
        parts.append(f"PRIOR_TURNS ({len(history)}):")
        for i, (turn, obs) in enumerate(history, 1):
            view = _action_to_sentinel_dict(turn.action)
            thought_one_line = " ".join(turn.thought.split())[:240]
            parts.append(
                f"--- Turn {i} ---\n"
                f"Thought: {thought_one_line}\n"
                f"Action: {view['Action']}\n"
                f"Action_Input: {json.dumps(view['Action_Input'], separators=(',', ':'), ensure_ascii=False)}\n"
                f"Observation: {_observation_to_text(obs)}"
            )

    if extra_hint:
        parts.append(f"[HINT]\n{extra_hint}")

    return "\n\n".join(parts)


def parse_sentinel_output(raw: str, *, base_url: str) -> ModelTurn:
    """Parse the model's single-JSON output into a ModelTurn.

    Raises SentinelParseError on any structural problem (invalid JSON, missing
    keys, unknown action, or pydantic validation failure on the mapped Action).
    """
    if not raw or not raw.strip():
        raise SentinelParseError("empty response")

    text = _strip_fences(raw.strip())
    obj = _load_first_json_object(text)

    if not isinstance(obj, dict):
        raise SentinelParseError(f"expected JSON object, got {type(obj).__name__}")

    thought = str(obj.get("Thought", "")).strip()
    sentinel_action = str(obj.get("Action", "")).strip()
    action_input = obj.get("Action_Input") or {}
    if not isinstance(action_input, dict):
        action_input = {}

    if sentinel_action not in VALID_SENTINEL_ACTIONS:
        raise SentinelParseError(f"unknown SENTINEL action: {sentinel_action!r}")

    try:
        agent_action = _map_action(sentinel_action, action_input, base_url=base_url)
        return ModelTurn(thought=thought, action=agent_action)
    except ValidationError as e:
        raise SentinelParseError(f"action validation failed: {e}") from e


# ─── internals ────────────────────────────────────────────────────────────────

def _strip_fences(s: str) -> str:
    if s.startswith("```json"):
        s = s[len("```json"):]
    elif s.startswith("```"):
        s = s[3:]
    if s.rstrip().endswith("```"):
        s = s.rstrip()[:-3]
    return s.strip()


def _load_first_json_object(s: str) -> Any:
    """Tolerant JSON loader: handles trailing garbage / extra text after the object."""
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass

    start = s.find("{")
    if start < 0:
        raise SentinelParseError("no JSON object found in response")

    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(s)):
        c = s[i]
        if esc:
            esc = False
            continue
        if c == "\\":
            esc = True
            continue
        if c == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                candidate = s[start : i + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError as e:
                    raise SentinelParseError(f"balanced scan found invalid JSON: {e}") from e
    raise SentinelParseError("unterminated JSON object")


def _map_action(
    action: str,
    ai: dict[str, Any],
    *,
    base_url: str,
) -> Action:
    """Translate a SENTINEL action + Action_Input dict into an agent Action."""
    target_url_raw = str(ai.get("target_url") or "")
    target_url = _absolutize(target_url_raw, base_url)
    method_raw = str(ai.get("method") or "GET").upper()
    method = HttpMethod.POST if method_raw == "POST" else HttpMethod.GET
    parameters = ai.get("parameters") or {}
    rationale = str(ai.get("rationale") or "")

    if action in ("SQL_INJECT", "XSS_INJECT", "RETRY_MUTATED"):
        vuln = VulnClass.XSS if action == "XSS_INJECT" else VulnClass.SQLI

        if not isinstance(parameters, dict) or not parameters:
            # No usable parameters — drop to a deeper-crawl so the loop doesn't stall.
            return CrawlDeeper(reason=f"{action} emitted with no parameters")

        if len(parameters) >= 2:
            # Multi-field submission → use SubmitForm so Playwright drives the browser
            # and captures session cookies. The agent's AUTHENTICATED goal checker
            # depends on cookies arriving via the browser, not via raw httpx.
            fields = {str(k): str(v) for k, v in parameters.items()}
            return SubmitForm(form_selector="form", fields=fields)

        # Exactly one parameter — direct INJECT_PAYLOAD against the endpoint.
        ((param_name, payload),) = parameters.items()
        return InjectPayload(
            url=target_url or base_url,
            method=method,
            param_name=str(param_name),
            payload=str(payload),
            vuln_class=vuln,
        )

    if action == "CRAWL_DEEPER":
        return CrawlDeeper(reason=rationale or "model requested deeper crawl")

    if action == "WAIT":
        secs_raw = ai.get("seconds") or ai.get("wait_seconds")
        try:
            secs = int(secs_raw) if secs_raw else 5
        except (TypeError, ValueError):
            secs = 5
        secs = max(1, min(30, secs))
        return Wait(reason=rationale or "model requested wait", seconds=secs)

    if action == "ANALYZE_RESPONSE":
        signal = str(ai.get("signal") or "analyze")
        # No-op tool turn: 1-second wait so the next iteration sees the same DOM.
        return Wait(reason=f"analyze:{signal}", seconds=1)

    if action == "STOP":
        success = str(ai.get("success_state") or "unknown")
        # Strip any stale [STOP success_state=...] prefix that may have leaked in
        # from the history window so we never nest multiple prefixes.
        raw_evidence = str(ai.get("evidence") or rationale or "model declared STOP")
        evidence = _strip_stop_prefix(raw_evidence)
        return ReportFinding(
            vuln_type=VulnClass.SQLI,
            url=target_url or base_url,
            evidence=f"[STOP success_state={success}] {evidence}",
            severity="high",
        )

    # Unreachable: validated above.
    raise SentinelParseError(f"unmapped action: {action!r}")


def _absolutize(url: str, base_url: str) -> str:
    if not url:
        return ""
    if url.startswith(("http://", "https://")):
        return url
    base = base_url.rstrip("/")
    if url.startswith("/"):
        return f"{base}{url}"
    return f"{base}/{url}"


# Matches the prefix injected by _map_action's STOP branch so we can strip it
# when re-surfacing evidence in history or on a repeated STOP action.
_STOP_PREFIX_RE = re.compile(r"^(?:\[STOP success_state=[^\]]*\]\s*)+")


def _strip_stop_prefix(text: str) -> str:
    """Remove one or more leading '[STOP success_state=...] ' prefixes."""
    return _STOP_PREFIX_RE.sub("", text).strip()


def _observation_to_text(obs: Observation) -> str:
    parts = [f"HTTP {obs.status}"]
    if obs.content_delta:
        parts.append(f"delta={obs.content_delta}")
    if obs.payload_reflected:
        parts.append("reflected=true")
    if obs.error_keywords:
        parts.append(f"errors={','.join(obs.error_keywords)}")
    if obs.new_cookies:
        parts.append(f"new_cookies={','.join(obs.new_cookies)}")
    if obs.note:
        parts.append(obs.note)
    return " | ".join(parts)


def _action_to_sentinel_dict(action: Action) -> dict[str, Any]:
    """Reverse-map agent Action back to a SENTINEL dict for PRIOR_TURNS rendering."""
    if isinstance(action, InjectPayload):
        return {
            "Action": "XSS_INJECT" if action.vuln_class == VulnClass.XSS else "SQL_INJECT",
            "Action_Input": {
                "target_url": action.url,
                "method": action.method.value,
                "parameters": {action.param_name: action.payload},
                "headers": {},
                "rationale": "",
            },
        }
    if isinstance(action, SubmitForm):
        return {
            "Action": "SQL_INJECT",
            "Action_Input": {
                "target_url": "",
                "method": "POST",
                "parameters": dict(action.fields),
                "headers": {},
                "rationale": f"form_selector={action.form_selector}",
            },
        }
    if isinstance(action, Navigate):
        return {
            "Action": "CRAWL_DEEPER",
            "Action_Input": {
                "target_url": action.url,
                "method": "GET",
                "parameters": {},
                "headers": {},
                "rationale": "navigate",
            },
        }
    if isinstance(action, CrawlDeeper):
        return {
            "Action": "CRAWL_DEEPER",
            "Action_Input": {
                "target_url": "",
                "method": "GET",
                "parameters": {},
                "headers": {},
                "rationale": action.reason,
            },
        }
    if isinstance(action, Wait):
        if action.reason.startswith("analyze:"):
            return {
                "Action": "ANALYZE_RESPONSE",
                "Action_Input": {
                    "target_url": "",
                    "method": "n/a",
                    "parameters": {},
                    "headers": {},
                    "rationale": action.reason,
                    "signal": action.reason.removeprefix("analyze:"),
                    "next_recommended": "CRAWL_DEEPER",
                },
            }
        return {
            "Action": "WAIT",
            "Action_Input": {
                "target_url": "",
                "method": "n/a",
                "parameters": {},
                "headers": {},
                "rationale": action.reason,
                "seconds": action.seconds,
            },
        }
    if isinstance(action, ReportFinding):
        return {
            "Action": "STOP",
            "Action_Input": {
                "target_url": action.url,
                "method": "n/a",
                "parameters": {},
                "headers": {},
                "rationale": "finding reported",
                "success_state": "authenticated_dashboard",
                # Strip the bridge-added prefix so the model sees clean evidence
                # in PRIOR_TURNS and does not re-generate nested prefixes.
                "evidence": _strip_stop_prefix(action.evidence),
            },
        }
    return {
        "Action": "WAIT",
        "Action_Input": {
            "target_url": "",
            "method": "n/a",
            "parameters": {},
            "headers": {},
            "rationale": f"unmapped action type: {type(action).__name__}",
            "seconds": 1,
        },
    }
