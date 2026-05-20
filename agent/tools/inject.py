"""INJECT_PAYLOAD handler.

Outcome cache check happens BEFORE execution: identical attacks across runs are
satisfied from sqlite without re-issuing the HTTP request (plan §6c).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable

from agent.browser import Browser
from agent.cache import OutcomeCache
from agent.schemas import Action, InjectPayload, ToolResult
from agent.state import AgentState

log = logging.getLogger(__name__)


def _scope_ok(url: str, base: str) -> bool:
    return url.startswith(base)


def make_inject_payload(
    browser: Browser,
    state: AgentState,
    outcome_cache: OutcomeCache | None = None,
) -> Callable[[Action], Awaitable[ToolResult]]:
    async def handler(action: Action) -> ToolResult:
        assert isinstance(action, InjectPayload)
        if not _scope_ok(action.url, state.base_url):
            return ToolResult(ok=False, error=f"out of scope: {action.url}", url=action.url)

        if outcome_cache is not None:
            cached = outcome_cache.get(
                action.url, action.method.value, action.param_name, action.payload
            )
            if cached is not None:
                log.info(
                    "outcome cache hit url=%s param=%s",
                    action.url,
                    action.param_name,
                )
                state.mark_attempt(action.url, action.param_name, action.payload)
                return ToolResult(
                    ok=cached["ok"],
                    status=cached["status"],
                    url=action.url,
                    body_summary=cached["body_summary"],
                    raw_body_excerpt=cached["body_summary"],
                    error="cache_hit",
                )

        if state.already_attempted(action.url, action.param_name, action.payload):
            return ToolResult(
                ok=False,
                error="duplicate attempt within run",
                url=action.url,
            )

        state.mark_attempt(action.url, action.param_name, action.payload)
        t0 = time.monotonic()
        result = await browser.inject(
            url=action.url,
            method=action.method.value,
            param=action.param_name,
            payload=action.payload,
        )
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        state.cookies.update(result.cookies)
        if outcome_cache is not None:
            outcome_cache.put(
                action.url,
                action.method.value,
                action.param_name,
                action.payload,
                status=result.status,
                ok=200 <= result.status < 400,
                body_summary=result.body_summary,
                payload_reflected=action.payload in result.body_excerpt,
                error_keywords=[],
            )

        return ToolResult(
            ok=200 <= result.status < 500,
            status=result.status,
            url=action.url,
            body_summary=result.body_summary,
            dom_changed=True,
            new_cookies=list(result.new_cookies),
            elapsed_ms=elapsed_ms,
            raw_body_excerpt=result.body_excerpt,
        )

    return handler
