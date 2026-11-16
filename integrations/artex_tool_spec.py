"""Build an ARTEX custom command tool for the local scan bridge."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def build_spec(repo: Path, scope: Path, python: Path, target_config: Path | None = None,
               profile: str = "quick") -> dict:
    repo = repo.resolve()
    scope = scope.resolve()
    python = python.resolve()
    command = [str(python), "-m", "integrations.artex_bridge", "{url}",
               "--scope", str(scope), "--profile", profile, "--output", "{output}"]
    if target_config is not None:
        command.extend(["--target-config", str(target_config.resolve())])
    code = (
        "import json, subprocess, sys, tempfile\n"
        "params = json.load(sys.stdin)\n"
        "url = params.get('url')\n"
        "if not isinstance(url, str) or not url.startswith(('http://', 'https://')):\n"
        "    print(json.dumps({'schema': 'artex-bridge/v1', 'ok': False, 'error': 'invalid_url'}))\n"
        "    raise SystemExit(1)\n"
        "output = tempfile.mkdtemp(prefix='artex-bugbounty-')\n"
        f"command = {command!r}\n"
        "command = [output if part == '{output}' else url if part == '{url}' else part for part in command]\n"
        f"try:\n    result = subprocess.run(command, cwd={str(repo)!r}, capture_output=True, text=True, timeout=900)\n"
        "except subprocess.TimeoutExpired:\n"
        "    print(json.dumps({'schema': 'artex-bridge/v1', 'ok': False, 'error': 'scan_timeout'}))\n"
        "    raise SystemExit(1)\n"
        "print(result.stdout if result.stdout.strip() else json.dumps("
        "{'schema': 'artex-bridge/v1', 'ok': False, 'error': 'scan_failed', "
        "'detail': result.stderr[-1000:]}))\n"
        "raise SystemExit(result.returncode)\n"
    )
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
        "kind": "script",
        "exec": {"code": code, "timeout_ms": 930000},
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
