"""Tool registry: dispatches a validated Action to its async handler."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from agent.schemas import Action, ToolName, ToolResult

log = logging.getLogger(__name__)

ToolHandler = Callable[[Action], Awaitable[ToolResult]]


class ToolRegistry:
    def __init__(self) -> None:
        self._handlers: dict[ToolName, ToolHandler] = {}

    def register(self, name: ToolName, handler: ToolHandler) -> None:
        self._handlers[name] = handler

    async def dispatch(self, action: Action) -> ToolResult:
        handler = self._handlers.get(action.name)
        if handler is None:
            return ToolResult(ok=False, error=f"no handler for {action.name}")
        try:
            return await handler(action)
        except Exception as e:  # noqa: BLE001
            log.exception("tool %s raised", action.name)
            return ToolResult(ok=False, error=f"{type(e).__name__}: {e}")
