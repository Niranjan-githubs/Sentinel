"""OpenAI-compatible inference client (plan §11 step 7).

Talks to Ollama / vLLM / llama.cpp's OpenAI-compat /v1/chat/completions. Includes:
  - exponential-backoff retry on transient errors
  - SENTINEL single-JSON output parser (via agent.sentinel_bridge)
  - 1-shot strict reminder if the first parse attempt fails (plan §7 L1)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from openai import (
    APIConnectionError,
    APIError,
    AsyncOpenAI,
    AuthenticationError,
    RateLimitError,
)
from pydantic import ValidationError
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from agent.schemas import ModelTurn
from agent.sentinel_bridge import SentinelParseError, parse_sentinel_output

log = logging.getLogger(__name__)


# Re-exported under the legacy name so callers that catch ParseError still work.
ParseError = SentinelParseError


@dataclass
class InferenceConfig:
    endpoint: str
    api_key: str
    model: str
    temperature: float
    top_p: float
    max_tokens: int
    request_timeout_s: float
    base_url: str = ""  # target base URL; used by SENTINEL bridge to absolutize URLs


class InferenceClient:
    def __init__(self, cfg: InferenceConfig):
        self._cfg = cfg
        self._client = AsyncOpenAI(
            api_key=cfg.api_key or "dummy-key",
            base_url=cfg.endpoint.rstrip("/"),
            timeout=cfg.request_timeout_s,
        )

    async def health(self) -> bool:
        """Probe the endpoint. Raises ``AuthenticationError`` on 401 so the
        orchestrator can fail fast; returns False for any other failure."""
        try:
            await self._client.models.list()
            return True
        except AuthenticationError:
            raise
        except Exception as e:  # noqa: BLE001
            log.warning("inference health check failed: %s", e)
            return False

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(min=1, max=8),
        retry=retry_if_exception_type((APIConnectionError, RateLimitError, APIError)),
        reraise=True,
    )
    async def _chat(self, system: str, user: str) -> str:
        resp = await self._client.chat.completions.create(
            model=self._cfg.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=self._cfg.temperature,
            top_p=self._cfg.top_p,
            max_tokens=self._cfg.max_tokens,
        )
        return resp.choices[0].message.content or ""

    async def reason(self, system: str, user: str) -> ModelTurn:
        raw = await self._chat(system, user)
        return parse_sentinel_output(raw, base_url=self._cfg.base_url)

    async def reason_with_strict_retry(self, system: str, user: str) -> ModelTurn:
        try:
            return await self.reason(system, user)
        except (SentinelParseError, ValidationError, json.JSONDecodeError) as e:
            log.info("first parse failed (%s); retrying with strict reminder", e)
            stricter = (
                user
                + "\n\nSYSTEM REMINDER: Your previous reply could not be parsed. "
                "Output ONLY a single JSON object with exactly the keys "
                "'Thought', 'Action', and 'Action_Input'. No prose, no markdown "
                "fences. 'Action' must be one of: SQL_INJECT | XSS_INJECT | "
                "RETRY_MUTATED | ANALYZE_RESPONSE | CRAWL_DEEPER | WAIT | STOP."
            )
            raw = await self._chat(system, stricter)
            return parse_sentinel_output(raw, base_url=self._cfg.base_url)
