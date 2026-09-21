from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from core.fingerprint import build_environment_fingerprint
from core.orchestrator import run_sample_pipeline
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from testcase.loader import load_testcases


DEFAULT_SCOPE = Path("config/scope.example.yaml")
DEFAULT_TESTCASES = Path("testcase/suites/basic.yaml")


def _json(data: object) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def cmd_doctor(_: argparse.Namespace) -> int:
    from shutil import which
    import platform
    import sys

    tools = ["promptfoo", "garak", "pyrit", "nuclei", "dalfox", "trufflehog"]
    print(f"[OK] Python {sys.version.split()[0]}")
    print(f"[OK] Platform {platform.platform()}")
    for tool in tools:
        status = "OK" if which(tool) else "WARN"
        detail = which(tool) or "not installed"
        print(f"[{status}] {tool} {detail}")
    return 0


def cmd_fingerprint(args: argparse.Namespace) -> int:
    fp = build_environment_fingerprint(
        {
            "target_build": args.target_build,
            "model_provider": "fake",
            "model_name": "fake-llm",
            "model_version": "offline",
            "temperature": 0,
            "seed": 0,
            "system_prompt_hash": "none",
            "tool_schema_hash": "none",
            "rag_corpus_hash": "none",
            "testcase_version": "basic",
        }
    )
    print(_json(fp))
    return 0


def cmd_validate_scope(args: argparse.Namespace) -> int:
    engine = PolicyEngine.from_yaml(args.scope)
    decision = engine.validate_url(args.url)
    print(_json(decision.to_dict()))
    return 0 if decision.allowed else 2


def cmd_sample_run(args: argparse.Namespace) -> int:
    testcases = load_testcases(args.testcases)
    engine = PolicyEngine.from_yaml(args.scope)
    store = SQLiteStore(args.db)
    result = asyncio.run(run_sample_pipeline(engine, testcases, store, target_kind=args.target))
    print(_json(result))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm-bugbounty",
        description="Authorized LLM security testing automation pipeline",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="Check local runtime and optional tools")
    doctor.set_defaults(func=cmd_doctor)

    fingerprint = sub.add_parser("fingerprint", help="Create a reproducibility fingerprint")
    fingerprint.add_argument("--target-build", default="local")
    fingerprint.set_defaults(func=cmd_fingerprint)

    validate = sub.add_parser("validate-scope", help="Validate a URL against scope and policy")
    validate.add_argument("--scope", type=Path, default=DEFAULT_SCOPE)
    validate.add_argument("--url", required=True)
    validate.set_defaults(func=cmd_validate_scope)

    sample = sub.add_parser("sample-run", help="Run the offline fake target pipeline")
    sample.add_argument("--scope", type=Path, default=DEFAULT_SCOPE)
    sample.add_argument("--testcases", type=Path, default=DEFAULT_TESTCASES)
    sample.add_argument("--db", type=Path, default=Path("runs/sample.sqlite"))
    sample.add_argument("--target", choices=["fake-llm", "fake-agent", "fake-rag"], default="fake-llm")
    sample.set_defaults(func=cmd_sample_run)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
