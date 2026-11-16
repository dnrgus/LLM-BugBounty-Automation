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
            "and pack execution coverage. The ARTEX bridge records observed assets, candidate "
            "facts, skipped coverage, and evidence-backed confirmed findings automatically. "
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


def build_verify_spec(repo: Path, scope: Path, python: Path,
                      auth_contexts: Path | None = None) -> dict:
    repo, scope, python = repo.resolve(), scope.resolve(), python.resolve()
    command = [str(python), "-m", "integrations.artex_verify", "--candidate", "{candidate}",
               "--scope", str(scope), "--output", "{output}"]
    if auth_contexts is not None:
        command += ["--auth-contexts", str(auth_contexts.resolve())]
    code = (
        "import json, pathlib, subprocess, sys, tempfile\n"
        "candidate = json.load(sys.stdin)\n"
        "output = pathlib.Path(tempfile.mkdtemp(prefix='artex-verify-'))\n"
        "path = output / 'candidate.json'\n"
        "path.write_text(json.dumps(candidate), encoding='utf-8')\n"
        f"command = {command!r}\n"
        "command = [str(path) if part == '{candidate}' else str(output) if part == '{output}' else part for part in command]\n"
        f"try:\n    result = subprocess.run(command, cwd={str(repo)!r}, capture_output=True, text=True, timeout=60)\n"
        "except subprocess.TimeoutExpired:\n"
        "    print(json.dumps({'schema':'artex-verify/v1','status':'unavailable','reason':'verification timeout'}))\n"
        "    raise SystemExit(0)\n"
        "print(result.stdout if result.stdout.strip() else json.dumps({'schema':'artex-verify/v1','status':'unavailable','reason':result.stderr[-1000:]}))\n"
        "raise SystemExit(0)\n"
    )
    return {
        "key": "bugbounty_verify", "description": (
            "Verify a worker-discovered HTTP response differential candidate. Requires target_url, "
            "method, auth_context, prerequisites, success_criteria, observed_evidence, and "
            "vulnerability_type. Supports GET body_contains with control_url; unsupported types "
            "return unavailable. Scope, program policy and request budget are enforced."),
        "schema": {"type": "object", "properties": {
            "candidate_id": {"type": "string"}, "title": {"type": "string"},
            "target_url": {"type": "string"}, "method": {"type": "string"},
            "auth_context": {"type": "string"},
            "prerequisites": {"type": "array", "items": {"type": "string"}},
            "success_criteria": {"type": "object"}, "observed_evidence": {"type": "object"},
            "vulnerability_type": {"type": "string"},
        }, "required": ["target_url", "method", "auth_context", "prerequisites",
                        "success_criteria", "observed_evidence", "vulnerability_type"]},
        "agents": ["worker"], "enabled": True, "kind": "script",
        "exec": {"code": code, "timeout_ms": 70000}, "deferred": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate ARTEX custom tool JSON")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--scope", type=Path, required=True)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--target-config", type=Path)
    parser.add_argument("--profile", choices=("quick", "llm", "agent", "rag", "web", "full"),
                        default="quick")
    parser.add_argument("--include-verify", action="store_true")
    parser.add_argument("--auth-contexts", type=Path)
    args = parser.parse_args(argv)
    scan_spec = build_spec(args.repo, args.scope, args.python, args.target_config, args.profile)
    value = [scan_spec, build_verify_spec(args.repo, args.scope, args.python, args.auth_contexts)] if args.include_verify else scan_spec
    print(json.dumps(value,
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
