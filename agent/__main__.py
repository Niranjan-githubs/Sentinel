"""CLI entry point.

    python -m agent run --config config/scenarios/login_bypass.yaml
    python -m agent replay artifacts/runs/<run_id>/log.jsonl
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from agent.config import load_config
from agent.observability import configure_logging
from agent.orchestrator import Orchestrator


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="agent", description="Autonomous web pentesting agent"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="Run a scenario")
    p_run.add_argument(
        "--config",
        default="config/default.yaml",
        help="path to scenario YAML (default: config/default.yaml)",
    )
    p_run.add_argument("--verbose", "-v", action="store_true")
    p_run.add_argument(
        "--live",
        action="store_true",
        help="disable headless mode — opens a visible Chromium window so you can watch actions live",
    )

    p_replay = sub.add_parser("replay", help="Pretty-print a run log")
    p_replay.add_argument("log_path", help="path to artifacts/runs/<id>/log.jsonl")

    args = parser.parse_args()

    if args.cmd == "run":
        configure_logging(logging.DEBUG if args.verbose else logging.INFO)
        cfg = load_config(args.config)
        if args.live:
            cfg.browser.headless = False
            logging.getLogger("agent").info(
                "--live mode: Chromium will open visibly. "
                "Do not close the browser window during the run."
            )
        return asyncio.run(Orchestrator(cfg).run())
    if args.cmd == "replay":
        return _replay(Path(args.log_path))
    return 1


def _replay(path: Path) -> int:
    if not path.exists():
        print(f"no such file: {path}", file=sys.stderr)
        return 1
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                print(f"!! malformed line: {line[:120]}", file=sys.stderr)
                continue
            if "event" in rec:
                print(f"[{rec.get('iter', '-'):>4}] EVENT {rec['event']}: {rec}")
                continue
            i = rec.get("iter", "-")
            action = rec.get("action") or {}
            obs = rec.get("observation") or {}
            print(
                f"[{i:>4}] {action.get('name', '?'):<14} "
                f"ok={rec.get('tool_ok')} status={rec.get('tool_status')} "
                f"refl={obs.get('payload_reflected')} "
                f"errs={','.join(obs.get('error_keywords', [])) or '-'} "
                f"url={rec.get('url', '-')}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
