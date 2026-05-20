"""Fallback ladder (plan §7).

Implements stuck detection (no progress for N iters) and a rule-based action of
last resort when the model output is unparseable or the agent is wedged.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import urljoin

from agent.schemas import Action, CrawlDeeper, Navigate, ToolResult
from agent.state import AgentState

log = logging.getLogger(__name__)

_HREF_RE = re.compile(r'href=[\'"]([^\'"#]+)[\'"]', re.IGNORECASE)


@dataclass
class FallbackConfig:
    stuck_threshold: int = 3
    same_target_attempts: int = 5
    json_parse_retries: int = 1


class StuckDetector:
    """Counts consecutive iterations without observable progress."""

    def __init__(self, threshold: int):
        self._threshold = max(1, threshold)

    def update(
        self,
        state: AgentState,
        last_result: ToolResult,
        observation_signal: bool,
    ) -> bool:
        progress = (
            last_result.dom_changed
            or bool(last_result.new_cookies)
            or observation_signal
        )
        if progress:
            state.consecutive_no_progress = 0
        else:
            state.consecutive_no_progress += 1
        return state.consecutive_no_progress >= self._threshold


def rule_based_action(state: AgentState, pruned_dom: str) -> Action:
    """Last-resort action when the model cannot be used.

    If the current URL has been hammered, navigate to an unvisited link in scope
    extracted from the pruned DOM. Otherwise, crawl deeper.
    """
    if state.attempts_against(state.current_url) >= 5:
        for href in _HREF_RE.findall(pruned_dom):
            if href.startswith("javascript:"):
                continue
            full = urljoin(state.current_url or state.base_url, href)
            if full.startswith(state.base_url) and full not in state.visited_urls:
                return Navigate(url=full)
        return Navigate(url=state.base_url)
    return CrawlDeeper(reason="rule-based fallback (model unparseable)")


def stuck_hint(state: AgentState) -> str:
    return (
        f"You have made no progress for {state.consecutive_no_progress} iterations. "
        "Re-examine the DOM for unattempted vulnerability sinks (action, formaction, "
        "src, href, value, name, on*= handlers). If none remain on this page, "
        "issue NAVIGATE or CRAWL_DEEPER to a new endpoint."
    )


def saturation_hint(state: AgentState) -> str:
    return (
        f"You have attacked {state.current_url} {state.attempts_against(state.current_url)} "
        "times without success. Move on: issue NAVIGATE or CRAWL_DEEPER."
    )
