"""Pydantic models for tool actions, observations, and tool results.

Plan refs:
  - §4 tool layer (NAVIGATE / CRAWL_DEEPER / INJECT_PAYLOAD / SUBMIT_FORM /
    REPORT_FINDING / WAIT)
  - §3d sliding-window observation summary

The model emits ``Action`` JSON; the agent validates with pydantic and dispatches
through the tool registry. Strict (extra=forbid) so off-schema fields never sneak
through. Frozen so an action cannot be mutated mid-execution.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field


class ToolName(str, Enum):
    NAVIGATE = "NAVIGATE"
    CRAWL_DEEPER = "CRAWL_DEEPER"
    INJECT_PAYLOAD = "INJECT_PAYLOAD"
    SUBMIT_FORM = "SUBMIT_FORM"
    REPORT_FINDING = "REPORT_FINDING"
    WAIT = "WAIT"


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"


class VulnClass(str, Enum):
    SQLI = "SQLI"
    XSS = "XSS"


class _ActionBase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Navigate(_ActionBase):
    name: Literal[ToolName.NAVIGATE] = ToolName.NAVIGATE
    url: str


class CrawlDeeper(_ActionBase):
    name: Literal[ToolName.CRAWL_DEEPER] = ToolName.CRAWL_DEEPER
    reason: str = ""


class InjectPayload(_ActionBase):
    name: Literal[ToolName.INJECT_PAYLOAD] = ToolName.INJECT_PAYLOAD
    url: str
    method: HttpMethod = HttpMethod.GET
    target_selector: str | None = None
    param_name: str
    payload: str
    vuln_class: VulnClass


class SubmitForm(_ActionBase):
    name: Literal[ToolName.SUBMIT_FORM] = ToolName.SUBMIT_FORM
    form_selector: str
    fields: dict[str, str]


class ReportFinding(_ActionBase):
    name: Literal[ToolName.REPORT_FINDING] = ToolName.REPORT_FINDING
    vuln_type: VulnClass
    url: str
    param: str | None = None
    payload: str | None = None
    evidence: str
    severity: Literal["low", "medium", "high", "critical"] = "medium"


class Wait(_ActionBase):
    name: Literal[ToolName.WAIT] = ToolName.WAIT
    reason: str
    seconds: int = Field(default=5, ge=1, le=30)


Action = Annotated[
    Union[Navigate, CrawlDeeper, InjectPayload, SubmitForm, ReportFinding, Wait],
    Field(discriminator="name"),
]


class ModelTurn(BaseModel):
    """One Thought + Action emitted by the model in a single turn."""

    model_config = ConfigDict(extra="ignore")
    thought: str
    action: Action


class ToolResult(BaseModel):
    """Raw result of executing a tool. Becomes the input to observation synthesis."""

    model_config = ConfigDict(extra="ignore")
    ok: bool
    status: int = 0
    url: str = ""
    body_summary: str = ""
    dom_changed: bool = False
    new_cookies: list[str] = Field(default_factory=list)
    error: str | None = None
    elapsed_ms: int = 0
    raw_body_excerpt: str = ""


class Observation(BaseModel):
    """Compact observation written into the next prompt's history window."""

    model_config = ConfigDict(extra="ignore")
    status: int
    ok: bool
    body_size: int = 0
    content_delta: int = 0
    error_keywords: list[str] = Field(default_factory=list)
    payload_reflected: bool = False
    new_cookies: list[str] = Field(default_factory=list)
    note: str = ""
