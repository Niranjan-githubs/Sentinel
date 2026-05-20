"""Main orchestration loop: perceive -> think -> validate -> act -> observe -> goal-check.

Wires every component from the plan together. Bounded by per-iter, per-call,
and wall-time budgets so runs always terminate.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from openai import AuthenticationError

from agent.browser import Browser
from agent.cache import DomCache, OutcomeCache
from agent.config import RuntimeConfig
from agent.dom_prune import prune_with_cap
from agent.fallback import (
    FallbackConfig,
    StuckDetector,
    rule_based_action,
    saturation_hint,
    stuck_hint,
)
from agent.goals import get as get_goal_predicate
from agent.inference import InferenceClient, InferenceConfig, ParseError
from agent.observability import RunArtifacts, synthesize_observation
from agent.sentinel_bridge import SENTINEL_SYSTEM_PROMPT, build_sentinel_user_prompt
from agent.schemas import (
    Action,
    InjectPayload,
    ModelTurn,
    Navigate,
    ReportFinding,
    SubmitForm,
    ToolName,
    ToolResult,
)
from agent.state import AgentState
from agent.tools.inject import make_inject_payload
from agent.tools.navigate import make_crawl_deeper, make_navigate, make_submit_form
from agent.tools.registry import ToolRegistry
from agent.tools.report import make_report_finding, make_wait

log = logging.getLogger(__name__)


class Orchestrator:
    def __init__(self, cfg: RuntimeConfig):
        self._cfg = cfg
        self._state = AgentState(
            base_url=cfg.target.base_url,
            goal=cfg.goal,
            history_capacity=cfg.pruning.history_window,
        )
        self._inference = InferenceClient(
            InferenceConfig(
                endpoint=cfg.model.endpoint,
                api_key=cfg.model.api_key,
                model=cfg.model.name,
                temperature=cfg.model.temperature,
                top_p=cfg.model.top_p,
                max_tokens=cfg.model.max_tokens,
                request_timeout_s=cfg.model.request_timeout_s,
                base_url=cfg.target.base_url,
            )
        )
        self._dom_cache = DomCache(cfg.cache.dom_lru_size)
        self._outcome_cache = (
            OutcomeCache(cfg.cache.outcome_db) if cfg.cache.outcome_db else None
        )
        self._fallback_cfg = FallbackConfig(
            stuck_threshold=cfg.fallback.stuck_threshold,
            same_target_attempts=cfg.fallback.same_target_attempts,
            json_parse_retries=cfg.fallback.json_parse_retries,
        )
        self._stuck = StuckDetector(self._fallback_cfg.stuck_threshold)
        self._goal_predicate = get_goal_predicate(cfg.goal)
        self._artifacts = RunArtifacts(cfg.observability.log_dir)
        self._browser: Browser | None = None
        self._registry: ToolRegistry | None = None
        self._prev_body_len: int = 0

    @property
    def state(self) -> AgentState:
        return self._state

    @property
    def artifacts(self) -> RunArtifacts:
        return self._artifacts

    async def run(self) -> int:
        log.info(
            "run start id=%s goal=%s base=%s",
            self._artifacts.run_id,
            self._cfg.goal,
            self._cfg.target.base_url,
        )
        self._artifacts.log(
            event="RUN_START",
            run_id=self._artifacts.run_id,
            goal=self._cfg.goal,
            base_url=self._cfg.target.base_url,
            model=self._cfg.model.name,
        )

        async with Browser(
            base_url=self._cfg.target.base_url,
            headless=self._cfg.browser.headless,
            user_agent=self._cfg.browser.user_agent,
            nav_timeout_ms=self._cfg.browser.navigation_timeout_ms,
        ) as browser:
            self._browser = browser
            self._registry = self._build_registry(browser)
            try:
                await self._inference_health_check()
            except AuthenticationError as e:
                log.error("inference auth rejected (401): %s", e)
                self._artifacts.log(event="INFERENCE_AUTH_FAILED", error=str(e))
                return self._terminate(3, f"auth_failed: {e}")
            except RuntimeError as e:
                log.error("inference unavailable — aborting: %s", e)
                self._artifacts.log(event="INFERENCE_UNAVAILABLE", error=str(e))
                return self._terminate(3, str(e))

            seed = await self._dispatch(Navigate(url=self._cfg.target.base_url))
            if not seed.ok:
                log.warning("seed navigation failed; continuing")
            return await self._loop()


    async def _inference_health_check(self) -> None:
        ok = await self._inference.health()
        self._artifacts.log(event="INFERENCE_HEALTH", ok=ok)
        if not ok:
            log.error(
                "inference endpoint unreachable at %s — aborting run. "
                "Make sure Ollama is running: 'ollama serve'",
                self._cfg.model.endpoint,
            )
            # Raise so run() catches it and terminates cleanly.
            raise RuntimeError(
                f"inference endpoint unavailable: {self._cfg.model.endpoint}"
            )

    def _build_registry(self, browser: Browser) -> ToolRegistry:
        reg = ToolRegistry()
        reg.register(ToolName.NAVIGATE, make_navigate(browser, self._state))
        reg.register(ToolName.CRAWL_DEEPER, make_crawl_deeper(browser, self._state))
        reg.register(
            ToolName.INJECT_PAYLOAD,
            make_inject_payload(browser, self._state, self._outcome_cache),
        )
        reg.register(
            ToolName.SUBMIT_FORM,
            make_submit_form(browser, self._state, artifacts=self._artifacts),
        )
        reg.register(ToolName.REPORT_FINDING, make_report_finding(self._state))
        reg.register(ToolName.WAIT, make_wait())
        return reg

    async def _loop(self) -> int:
        budgets = self._cfg.budgets
        assert self._browser is not None
        while True:
            self._state.iteration += 1

            if self._state.iteration > budgets.max_iterations:
                return self._terminate(2, "max_iterations")
            if self._state.model_calls >= budgets.max_model_calls:
                return self._terminate(2, "max_model_calls")
            if self._state.elapsed_seconds() > budgets.max_wall_seconds:
                return self._terminate(2, "max_wall_seconds")

            html = await self._browser.current_html()
            cached = self._dom_cache.get(self._state.current_url, html)
            if cached is not None:
                rendered_dom = cached
            else:
                pruned = prune_with_cap(
                    html,
                    self._state.current_url,
                    self._cfg.pruning.dom_token_cap,
                )
                rendered_dom = pruned.render()
                self._dom_cache.put(self._state.current_url, html, rendered_dom)

            user = build_sentinel_user_prompt(
                goal=self._cfg.goal,
                base_url=self._cfg.target.base_url,
                current_url=self._state.current_url,
                pruned_dom=rendered_dom,
                history=list(self._state.history),
                extra_hint=self._maybe_hint(),
            )

            self._state.model_calls += 1
            _connection_error = False
            try:
                turn = await self._inference.reason_with_strict_retry(SENTINEL_SYSTEM_PROMPT, user)
                self._state.consecutive_connection_failures = 0  # successful call
            except Exception as e:  # noqa: BLE001
                err_str = str(e)
                log.warning("model unparseable, falling back: %s", e)
                if "connection error" in err_str.lower() or "connection" in err_str.lower():
                    _connection_error = True
                    self._state.consecutive_connection_failures += 1
                    log.warning(
                        "Ollama connection failure %d/3",
                        self._state.consecutive_connection_failures,
                    )
                    if self._state.consecutive_connection_failures >= 3:
                        log.error(
                            "Ollama dropped %d connections in a row \u2014 aborting run. "
                            "Restart Ollama: 'ollama serve'",
                            self._state.consecutive_connection_failures,
                        )
                        self._artifacts.log(
                            event="INFERENCE_LOST",
                            iter=self._state.iteration,
                            consecutive_connection_failures=self._state.consecutive_connection_failures,
                        )
                        return self._terminate(3, "inference_lost")
                fallback_action = rule_based_action(self._state, rendered_dom)
                turn = ModelTurn(thought=f"[fallback] {e}", action=fallback_action)

            payload_for_obs = (
                turn.action.payload if isinstance(turn.action, InjectPayload) else None
            )

            # ── Live terminal summary so SQL/XSS payloads are visible during runs. ──
            _action_name = turn.action.__class__.__name__
            if isinstance(turn.action, InjectPayload):
                log.info(
                    "[iter %d] %s → %s param=%r payload=%r",
                    self._state.iteration,
                    turn.action.vuln_class.value,
                    turn.action.url,
                    turn.action.param_name,
                    turn.action.payload,
                )
            elif isinstance(turn.action, SubmitForm):
                log.info(
                    "[iter %d] SQL_INJECT (SubmitForm) selector=%r fields=%s",
                    self._state.iteration,
                    turn.action.form_selector,
                    turn.action.fields,
                )
            else:
                log.info(
                    "[iter %d] action=%s thought=%s",
                    self._state.iteration,
                    _action_name,
                    turn.thought[:120],
                )

            result = await self._dispatch(turn.action)

            obs = synthesize_observation(result, payload_for_obs, self._prev_body_len)
            self._prev_body_len = obs.body_size
            self._state.record_turn(turn, obs)
            self._state.last_action_status = (
                "ok" if result.ok else (result.error or "fail")
            )

            signal = bool(obs.error_keywords) or obs.payload_reflected or bool(obs.new_cookies)
            self._stuck.update(self._state, result, observation_signal=signal)

            # ── Log and screenshot BEFORE any early-exit so every iteration
            # ── (including the goal-reached one) has full evidence on disk.
            self._artifacts.log(
                iter=self._state.iteration,
                url=self._state.current_url,
                action=turn.action.model_dump(mode="json"),
                thought=turn.thought,
                tool_status=result.status,
                tool_ok=result.ok,
                tool_error=result.error,
                observation=obs.model_dump(),
                cookies_count=len(self._state.cookies),
                visited=len(self._state.visited_urls),
                attempted=len(self._state.attempted),
                model_calls=self._state.model_calls,
                consecutive_no_progress=self._state.consecutive_no_progress,
                consecutive_stop_actions=self._state.consecutive_stop_actions,
            )
            if self._cfg.observability.screenshots:
                await self._browser.screenshot(self._artifacts.shot_path(self._state.iteration))

            # ── Goal check — runs after logging so evidence is always saved. ──
            if self._goal_predicate(self._state, result):
                detail = self._state.goal_detail or "success"
                log.info(
                    "GOAL REACHED — %s at iter %d url=%s",
                    detail.upper(),
                    self._state.iteration,
                    self._state.current_url,
                )
                self._artifacts.log(
                    event="GOAL_REACHED",
                    goal_detail=detail,
                    iter=self._state.iteration,
                    url=self._state.current_url,
                    cookies=list(self._state.cookies.keys()),
                )
                return self._terminate(0, f"goal_reached:{detail}")

            # Track consecutive unconfirmed STOP actions. The fine-tuned model
            # sometimes hallucinates success and emits STOP repeatedly when the
            # goal predicate disagrees. After MAX_UNCONFIRMED_STOPS in a row we
            # terminate so the run doesn't spin forever.
            _MAX_UNCONFIRMED_STOPS = 2  # reduced from 3 — kill false-positive STOP loops faster
            if isinstance(turn.action, ReportFinding):
                self._state.consecutive_stop_actions += 1
                if self._state.consecutive_stop_actions >= _MAX_UNCONFIRMED_STOPS:
                    log.warning(
                        "model issued %d consecutive unconfirmed STOP actions; "
                        "goal predicate never triggered — terminating",
                        self._state.consecutive_stop_actions,
                    )
                    self._artifacts.log(
                        event="UNCONFIRMED_STOP_LIMIT",
                        iter=self._state.iteration,
                        consecutive_stop_actions=self._state.consecutive_stop_actions,
                    )
                    return self._terminate(1, "unconfirmed_stop_limit")
            else:
                self._state.consecutive_stop_actions = 0

    def _maybe_hint(self) -> str:
        if self._state.consecutive_no_progress >= self._fallback_cfg.stuck_threshold:
            return stuck_hint(self._state)
        if (
            self._state.attempts_against(self._state.current_url)
            >= self._fallback_cfg.same_target_attempts
        ):
            return saturation_hint(self._state)
        return ""

    async def _dispatch(self, action: Action) -> ToolResult:
        assert self._registry is not None
        result = await self._registry.dispatch(action)
        if result.url:
            self._state.current_url = result.url
        return result

    def _terminate(self, code: int, reason: str) -> int:
        summary: dict[str, Any] = {
            "event": "RUN_END",
            "reason": reason,
            "code": code,
            "iter": self._state.iteration,
            "findings": len(self._state.findings),
            "model_calls": self._state.model_calls,
            "elapsed_s": round(self._state.elapsed_seconds(), 2),
            "visited": len(self._state.visited_urls),
            "attempted": len(self._state.attempted),
        }
        self._artifacts.log(**summary)
        try:
            (self._artifacts.dir / "findings.json").write_text(
                json.dumps(self._state.findings, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:  # noqa: BLE001
            log.exception("failed to write findings.json")
        log.info("run end: %s", summary)
        self._artifacts.close()
        return code
