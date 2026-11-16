"""Build an ARTEX custom command tool for the local scan bridge."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path


def build_spec(repo: Path, scope: Path, python: Path, target_config: Path | None = None,
               profile: str = "quick") -> dict:
    repo = repo.resolve()
    scope = scope.resolve()
    python = python.resolve()
    command = (
        f"cd {shlex.quote(str(repo))} && "
        f"{shlex.quote(str(python))} -m integrations.artex_bridge {{url}} "
        f"--scope {shlex.quote(str(scope))} "
        f"--profile {shlex.quote(profile)} "
        "--output $(mktemp -d /tmp/artex-bugbounty-XXXXXXXX)"
    )
    if target_config is not None:
        command += f" --target-config {shlex.quote(str(target_config.resolve()))}"
    return {
        "key": "bugbounty_scan",
        "description": (
            "Scan an authorized URL. Returns JSON assets, confirmed findings, candidates, "
            "and pack execution coverage. Record assets with insert_assets; record candidate "
            "observations with record_fact; report only confirmed findings with report_finding. "
            "Use pack_executions to distinguish skipped tests from negative results."
        ),
        "schema": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "Authorized target URL"}},
            "required": ["url"],
        },
        "agents": ["worker"],
        "enabled": True,
        "kind": "command",
        "exec": {"command": command, "timeout_ms": 930000},
        "deferred": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate ARTEX custom tool JSON")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--scope", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--target-config", type=Path)
    parser.add_argument("--profile", choices=("quick", "llm", "agent", "rag", "web", "full"),
                        default="quick")
    args = parser.parse_args(argv)
    print(json.dumps(build_spec(args.repo, args.scope, args.python, args.target_config, args.profile),
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
