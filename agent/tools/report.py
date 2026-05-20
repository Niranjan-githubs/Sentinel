"""REPORT_FINDING and WAIT handlers (terminal/passive tools)."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

from agent.schemas import Action, ReportFinding, ToolResult, Wait
from agent.state import AgentState

log = logging.getLogger(__name__)


def make_report_finding(
    state: AgentState,
) -> Callable[[Action], Awaitable[ToolResult]]:
    async def handler(action: Action) -> ToolResult:
        assert isinstance(action, ReportFinding)
        finding = action.model_dump()
        state.findings.append(finding)
        log.info("FINDING %s: %s", action.vuln_type.value, action.evidence[:200])
        return ToolResult(
            ok=True,
            status=0,
            url=action.url,
            body_summary=f"reported {action.vuln_type.value} ({action.severity})",
        )

    return handler


def make_wait() -> Callable[[Action], Awaitable[ToolResult]]:
    async def handler(action: Action) -> ToolResult:
        assert isinstance(action, Wait)
        await asyncio.sleep(action.seconds)
        return ToolResult(
            ok=True,
            status=0,
            body_summary=f"waited {action.seconds}s: {action.reason}",
        )

    return handler
