"""YAML-backed runtime configuration (plan §10).

Scenarios may include ``extends: <relative-path>`` to inherit from a base file
(typically ``config/default.yaml``). Override merges deeply.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict

_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class TargetCfg(BaseModel):
    base_url: str
    name: str = "unknown"



class ModelCfg(BaseModel):
    endpoint: str
    api_key: str = "dummy-key"
    name: str
    temperature: float = 0.2
    top_p: float = 0.9
    max_tokens: int = 512
    request_timeout_s: float = 60.0


class BudgetsCfg(BaseModel):
    max_iterations: int = 50
    max_model_calls: int = 100
    max_wall_seconds: int = 600


class PruningCfg(BaseModel):
    dom_token_cap: int = 1500
    history_window: int = 5
    keep_attrs: list[str] = []


class FallbackCfg(BaseModel):
    stuck_threshold: int = 3
    same_target_attempts: int = 5
    json_parse_retries: int = 1


class CacheCfg(BaseModel):
    prefix: bool = True
    dom_lru_size: int = 256
    outcome_db: str | None = "artifacts/outcome.sqlite"


class BrowserCfg(BaseModel):
    headless: bool = True
    user_agent: str = ""
    navigation_timeout_ms: int = 15000


class ObservabilityCfg(BaseModel):
    log_dir: str = "artifacts/runs"
    screenshots: bool = True
    asciinema: bool = False


class RuntimeConfig(BaseModel):
    # `model` collides with pydantic's protected namespace; opt out so the
    # YAML key can stay ergonomic.
    model_config = ConfigDict(extra="ignore", protected_namespaces=())

    target: TargetCfg
    goal: str
    budgets: BudgetsCfg = BudgetsCfg()
    model: ModelCfg
    pruning: PruningCfg = PruningCfg()
    fallback: FallbackCfg = FallbackCfg()
    cache: CacheCfg = CacheCfg()
    browser: BrowserCfg = BrowserCfg()
    observability: ObservabilityCfg = ObservabilityCfg()


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _expand_env(value: Any) -> Any:
    """Recursively expand ``${VAR}`` references against os.environ.

    Unset variables are left as the literal ``${VAR}`` so misconfiguration is
    visible at validation time rather than silently producing empty strings.
    """
    if isinstance(value, str):
        return _ENV_VAR_RE.sub(
            lambda m: os.environ.get(m.group(1), m.group(0)), value
        )
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def load_config(path: str | Path) -> RuntimeConfig:
    p = Path(path)
    with open(p, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    if "extends" in data:
        ext_rel = data.pop("extends")
        ext_path = (p.parent / ext_rel).resolve()
        with open(ext_path, encoding="utf-8") as f:
            base = yaml.safe_load(f) or {}
        data = _deep_merge(base, data)

    data = _expand_env(data)
    cfg = RuntimeConfig.model_validate(data)

    # Fail fast on unresolved ${VAR} in secrets — better than discovering it
    # via 401s mid-run.
    if "${" in cfg.model.api_key:
        raise ValueError(
            f"model.api_key contains an unresolved env-var placeholder "
            f"({cfg.model.api_key!r}). Set the variable in your shell, e.g.:\n"
            f"  PowerShell:  $env:GROQ_API_KEY = 'gsk_...'\n"
            f"  bash/zsh:    export GROQ_API_KEY=gsk_..."
        )
    return cfg
