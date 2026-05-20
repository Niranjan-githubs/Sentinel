"""Playwright-based browser driver (plan §11 step 3).

Owns the browser lifecycle, the cookie store, and the four primitive operations
the agent needs:

  - fetch(url)                 — navigate and return DOM + status + cookies
  - submit_form(selector, fields)  — fill and submit an HTML form
  - inject(url, method, param, payload)  — issue an attack request, GET or POST
  - next_unvisited_link()      — discover frontier link inside scope

Bodies are exposed in two forms:
  - body_excerpt: up to 8 KB raw (analyzer reads this for keywords / reflection)
  - body_summary: <=600 chars, single-line, prompt-safe
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from playwright.async_api import (
    Browser as PWBrowser,
)
from playwright.async_api import (
    BrowserContext,
    Page,
    Playwright,
    async_playwright,
)

log = logging.getLogger(__name__)

BODY_EXCERPT_CHARS = 8000
BODY_SUMMARY_CHARS = 600

# Heuristic patterns for endpoints that typically perform external redirects.
# Skipping these prevents the agent from following an open-redirect challenge
# (e.g. Juice Shop's `./redirect?to=...`) into out-of-scope territory.
_REDIRECT_QUERY_PATTERNS = (
    "/redirect?",
    "/redir?",
    "?redirect=",
    "?next=",
    "?return=",
    "?to=",
    "?url=",
    "?goto=",
    "?continue=",
    "?destination=",
)


@dataclass
class FetchResult:
    url: str
    status: int
    body_excerpt: str
    body_summary: str
    cookies: dict[str, str] = field(default_factory=dict)
    new_cookies: set[str] = field(default_factory=set)
    raw_html: str = ""


def _summarize_body(body: str) -> str:
    s = body.replace("\n", " ").replace("\r", " ").strip()
    if len(s) <= BODY_SUMMARY_CHARS:
        return s
    return s[:BODY_SUMMARY_CHARS] + "..."


# Input types that Playwright's fill() refuses — must use check/uncheck instead.
_CHECK_TYPES = frozenset({"checkbox", "radio"})
# Input types with no meaningful text value — skip silently.
_SKIP_TYPES = frozenset({"submit", "button", "image", "reset", "file"})


async def _fill_field(locator, value: str) -> None:  # type: ignore[type-arg]
    """Type-aware field interaction: checkbox/radio → check/uncheck; others → fill.

    Avoids Playwright's ``Error: Input of type "checkbox" cannot be filled``
    which crashes the entire form submission when the form contains auxiliary
    inputs like a "Remember Me" toggle that the model passes in its parameters.
    """
    try:
        input_type = (
            await locator.get_attribute("type") or "text"
        ).strip().lower()
    except Exception:  # noqa: BLE001
        input_type = "text"

    if input_type in _SKIP_TYPES:
        return  # nothing useful to do with submit/button/file inputs

    if input_type in _CHECK_TYPES:
        # Treat any truthy string ("true", "on", "1", "yes", "checked") as check.
        want_checked = value.strip().lower() not in {"false", "off", "0", "no", "unchecked", ""}
        if want_checked:
            await locator.check()
        else:
            await locator.uncheck()
        return

    # All other inputs (text, email, password, number, search, url, tel, …)
    await locator.fill(value)


class Browser:
    def __init__(
        self,
        *,
        base_url: str,
        headless: bool = True,
        user_agent: str = "",
        nav_timeout_ms: int = 15000,
    ):
        self._base_url = base_url
        self._headless = headless
        self._user_agent = user_agent
        self._nav_timeout = nav_timeout_ms
        self._pw: Playwright | None = None
        self._browser: PWBrowser | None = None
        self._context: BrowserContext | None = None
        self._page: Page | None = None
        self._cookies_seen: set[str] = set()

    async def start(self) -> None:
        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(headless=self._headless)
        ctx_kwargs: dict = {}
        if self._user_agent:
            ctx_kwargs["user_agent"] = self._user_agent
        self._context = await self._browser.new_context(**ctx_kwargs)
        self._page = await self._context.new_page()
        self._page.set_default_navigation_timeout(self._nav_timeout)
        self._page.set_default_timeout(self._nav_timeout)

    async def close(self) -> None:
        try:
            if self._context is not None:
                await self._context.close()
            if self._browser is not None:
                await self._browser.close()
            if self._pw is not None:
                await self._pw.stop()
        except Exception:  # noqa: BLE001
            log.exception("error during browser close")

    async def __aenter__(self) -> Browser:
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def current_html(self) -> str:
        assert self._page is not None
        try:
            return await self._page.content()
        except Exception as e:  # noqa: BLE001
            log.warning("current_html failed: %s", e)
            return ""

    async def _build_result(self, url: str, status: int, html: str) -> FetchResult:
        cookies: dict[str, str] = {}
        if self._context is not None:
            try:
                for c in await self._context.cookies():
                    cookies[c["name"]] = c["value"]
            except Exception:  # noqa: BLE001
                log.exception("cookie read failed")
        new = {n for n in cookies if n not in self._cookies_seen}
        self._cookies_seen.update(cookies)
        return FetchResult(
            url=url,
            status=status,
            body_excerpt=html[:BODY_EXCERPT_CHARS],
            body_summary=_summarize_body(html),
            cookies=cookies,
            new_cookies=new,
            raw_html=html,
        )

    async def fetch(self, url: str) -> FetchResult:
        assert self._page is not None
        try:
            response = await self._page.goto(url, wait_until="domcontentloaded")
            status = response.status if response is not None else 0
            try:
                await self._page.wait_for_load_state("networkidle", timeout=3000)
            except Exception:  # noqa: BLE001
                pass
        except Exception as e:  # noqa: BLE001
            log.warning("nav error url=%s: %s", url, e)
            return FetchResult(
                url=url, status=0, body_excerpt="", body_summary=f"nav_error: {e}"
            )
        html = await self._page.content()
        return await self._build_result(self._page.url, status, html)

    async def submit_form(
        self,
        selector: str,
        fields: dict[str, str],
        pre_submit_shot_path: str | None = None,
    ) -> FetchResult:
        assert self._page is not None
        page = self._page
        try:
            # Fill each field — try scoped selector first, fall back to page-wide
            # [name='X'] or #X (Juice Shop login uses <input id="email"> with name="email").
            for name, value in fields.items():
                target = None
                for candidate in (
                    page.locator(f"{selector} [name='{name}']"),
                    page.locator(f"[name='{name}']"),
                    page.locator(f"#{name}"),
                    page.locator(f"input[id='{name}'], textarea[id='{name}']"),
                ):
                    if await candidate.count() > 0:
                        target = candidate
                        break
                if target is None:
                    log.warning("submit_form: no element matches field %r", name)
                    continue
                await _fill_field(target.first, value)

            # ── Pre-submit screenshot: payload is now visible in the fields. ──
            if pre_submit_shot_path:
                try:
                    await page.screenshot(path=pre_submit_shot_path, full_page=False)
                    log.info("pre-submit screenshot saved: %s", pre_submit_shot_path)
                except Exception:  # noqa: BLE001
                    log.warning("pre-submit screenshot failed")

            # Find the submit button — try scoped, then page-wide, then id-based fallbacks.
            submit_locator = None
            for candidate in (
                page.locator(f"{selector} button[type=submit], {selector} input[type=submit]"),
                page.locator("button[type=submit], input[type=submit]"),
                page.locator("button#loginButton, button#submitButton, button#registerButton"),
            ):
                if await candidate.count() > 0:
                    submit_locator = candidate
                    break
            if submit_locator is None:
                log.warning("submit_form: no submit button found")
                html = await page.content()
                return await self._build_result(page.url, 0, html)

            pre_url = page.url
            try:
                async with page.expect_navigation(
                    wait_until="domcontentloaded", timeout=self._nav_timeout
                ) as nav_info:
                    await submit_locator.first.click()
                response = await nav_info.value
                status = response.status if response is not None else 0
                # If navigation happened but response is None (e.g. 302 redirect
                # consumed before we could intercept), check URL change as signal.
                if status == 0 and page.url != pre_url:
                    status = 200  # URL changed = redirect succeeded
            except Exception:
                # SPA forms post via XHR — no top-level navigation. Also fires
                # if the navigation completed before expect_navigation could hook.
                # Wait briefly for any XHR/redirect to settle, then check URL.
                try:
                    await page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:  # noqa: BLE001
                    await asyncio.sleep(1.0)
                # If URL changed after the click, it was a real redirect (e.g. DVWA login).
                status = 200 if page.url != pre_url else 0

        except Exception as e:  # noqa: BLE001
            log.warning("submit_form error: %s", e)
            html = await page.content()
            return await self._build_result(page.url, 0, html)
        html = await page.content()
        return await self._build_result(page.url, status, html)

    async def inject(
        self, *, url: str, method: str, param: str, payload: str
    ) -> FetchResult:
        method_u = method.upper()
        if method_u == "GET":
            target = _set_query_param(url, param, payload)
            return await self.fetch(target)

        # POST: use context.request so session cookies are preserved.
        assert self._context is not None
        try:
            response = await self._context.request.post(
                url, form={param: payload}, timeout=self._nav_timeout
            )
            text = await response.text()
            return await self._build_result(url, response.status, text)
        except Exception as e:  # noqa: BLE001
            log.warning("inject POST error url=%s: %s", url, e)
            return FetchResult(
                url=url, status=0, body_excerpt="", body_summary=f"post_error: {e}"
            )

    async def next_unvisited_link(
        self, visited: set[str], base: str
    ) -> str | None:
        assert self._page is not None
        try:
            hrefs = await self._page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)"
            )
        except Exception as e:  # noqa: BLE001
            log.warning("link discovery failed: %s", e)
            return None
        for h in hrefs:
            if not h or h.startswith("javascript:"):
                continue
            if not h.startswith(base):
                continue
            if h in visited:
                continue
            h_low = h.lower()
            if any(p in h_low for p in _REDIRECT_QUERY_PATTERNS):
                continue
            return h
        return None

    async def screenshot(self, path: str) -> None:
        if self._page is None:
            return
        try:
            await self._page.screenshot(path=path, full_page=False)
        except Exception:  # noqa: BLE001
            log.exception("screenshot failed")


def _set_query_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    qs[param] = value
    return urlunparse(parsed._replace(query=urlencode(qs)))
