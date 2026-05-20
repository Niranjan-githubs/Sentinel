"""NAVIGATE / CRAWL_DEEPER / SUBMIT_FORM handlers."""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from urllib.parse import urljoin

from agent.browser import Browser
from agent.observability import RunArtifacts
from agent.schemas import Action, CrawlDeeper, Navigate, SubmitForm, ToolResult
from agent.state import AgentState

log = logging.getLogger(__name__)


def _scope_ok(url: str, base: str) -> bool:
    return url.startswith(base)


async def _fetch_with_scope_recovery(
    browser: Browser, url: str, base_url: str
) -> tuple[object, str]:
    """Fetch URL; if redirects landed out of scope, recover to base.

    Returns (FetchResult, recovery_note). recovery_note is "" on clean nav.
    """
    result = await browser.fetch(url)
    if result.url and not result.url.startswith(base_url):
        log.warning(
            "navigation landed out of scope (%s); recovering to base %s",
            result.url,
            base_url,
        )
        recovered = await browser.fetch(base_url)
        return recovered, f"recovered_from_off_scope:{result.url}"
    return result, ""


def _nav_ok(status: int, final_url: str, prior_url: str) -> bool:
    """Treat SPA hash-route changes as success even when Playwright returns status=0.

    On Angular hash routes (#/login etc), the page renders new content without
    issuing a top-level navigation that has an HTTP response. We detect this by
    checking that the URL actually changed even though status is 0.
    """
    if status > 0:
        return True
    if final_url and final_url != prior_url:
        return True
    return False


def make_navigate(
    browser: Browser, state: AgentState
) -> Callable[[Action], Awaitable[ToolResult]]:
    async def handler(action: Action) -> ToolResult:
        assert isinstance(action, Navigate)
        url = action.url
        if not url.startswith(("http://", "https://")):
            url = urljoin(state.current_url or state.base_url, url)
        if not _scope_ok(url, state.base_url):
            return ToolResult(ok=False, error=f"out of scope: {url}", url=url)
        prior_url = state.current_url
        t0 = time.monotonic()
        result, note = await _fetch_with_scope_recovery(browser, url, state.base_url)
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        final_url = result.url or url
        state.visit(final_url)
        state.cookies.update(result.cookies)
        return ToolResult(
            ok=_nav_ok(result.status, final_url, prior_url),
            status=result.status,
            url=final_url,
            body_summary=result.body_summary,
            dom_changed=True,
            new_cookies=list(result.new_cookies),
            elapsed_ms=elapsed_ms,
            raw_body_excerpt=result.body_excerpt,
            error=note or None,
        )

    return handler


def make_crawl_deeper(
    browser: Browser, state: AgentState
) -> Callable[[Action], Awaitable[ToolResult]]:
    async def handler(action: Action) -> ToolResult:
        assert isinstance(action, CrawlDeeper)
        next_url = await browser.next_unvisited_link(state.visited_urls, state.base_url)
        if next_url is None:
            return ToolResult(
                ok=False,
                error="no unvisited links in scope",
                url=state.current_url,
            )
        prior_url = state.current_url
        t0 = time.monotonic()
        result, note = await _fetch_with_scope_recovery(
            browser, next_url, state.base_url
        )
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        final_url = result.url or next_url
        state.visit(final_url)
        state.cookies.update(result.cookies)
        return ToolResult(
            ok=_nav_ok(result.status, final_url, prior_url),
            status=result.status,
            url=final_url,
            body_summary=result.body_summary,
            dom_changed=True,
            new_cookies=list(result.new_cookies),
            elapsed_ms=elapsed_ms,
            raw_body_excerpt=result.body_excerpt,
            error=note or None,
        )

    return handler


def make_submit_form(
    browser: Browser,
    state: AgentState,
    artifacts: RunArtifacts | None = None,
) -> Callable[[Action], Awaitable[ToolResult]]:
    async def handler(action: Action) -> ToolResult:
        assert isinstance(action, SubmitForm)
        t0 = time.monotonic()
        # Generate a pre-submit screenshot path so the injected payload is
        # visible in the browser window (fields filled, submit not yet clicked).
        pre_shot: str | None = None
        if artifacts is not None:
            pre_shot = str(
                artifacts.shots_dir / f"iter_{state.iteration:04d}_presubmit.png"
            )
        result = await browser.submit_form(
            action.form_selector, action.fields, pre_submit_shot_path=pre_shot
        )
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        state.cookies.update(result.cookies)
        if result.url:
            state.visit(result.url)
        prior_url = state.current_url
        return ToolResult(
            ok=(200 <= result.status < 500) or (result.url != prior_url and result.url is not None),
            status=result.status,
            url=result.url,
            body_summary=result.body_summary,
            dom_changed=True,
            new_cookies=list(result.new_cookies),
            elapsed_ms=elapsed_ms,
            raw_body_excerpt=result.body_excerpt,
        )

    return handler
