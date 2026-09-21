from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from adapters.llm.garak import GarakAdapter
from adapters.llm.promptfoo import PromptfooAdapter
from adapters.llm.pyrit import PyRITAdapter
from attacks.adaptive import AdaptivePlanner
from attacks.mutation import MutationEngine, mutation_stats
from core.fingerprint import build_environment_fingerprint
from core.orchestrator import run_adaptive_pipeline, run_sample_pipeline
from core.tool_doctor import check_tools, write_tool_lock
from judges.benchmark import load_benchmark_cases, run_benchmark
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from targets.factory import create_target
from testcase.coverage import build_coverage_matrix, coverage_summary
from testcase.loader import load_testcases
from testcase.selector import select_executable_testcases


DEFAULT_SCOPE = Path("config/scope.example.yaml")
DEFAULT_TESTCASES = Path("testcase/suites/basic.yaml")
DEFAULT_JUDGE_BENCHMARK = Path("benchmarks/judge/baseline.json")
DEFAULT_TOOLS = Path("config/tools.yaml")


def _json(data: object) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def cmd_doctor(args: argparse.Namespace) -> int:
    snapshot = check_tools(args.tools)
    if args.write_lock:
        write_tool_lock(snapshot, args.lockfile)
    if args.json:
        print(_json(snapshot))
        return 0
    print(f"[OK] Python {snapshot['python']}")
    print(f"[OK] Platform {snapshot['platform']}")
    for tool in snapshot["tools"]:
        label = "OK" if tool["available"] else "WARN"
        detail = tool["version"] or tool["path"] or "not installed"
        print(f"[{label}] {tool['name']} {detail}")
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


def cmd_coverage(args: argparse.Namespace) -> int:
    testcases = load_testcases(args.testcases)
    target = create_target(args.target)
    capabilities = asyncio.run(target.capabilities())
    policy = PolicyEngine.from_yaml(args.scope)
    selected = select_executable_testcases(testcases, capabilities, policy)
    matrix = build_coverage_matrix(testcases, capabilities, {case.id for case in selected})
    payload = {
        "target": args.target,
        "summary": coverage_summary(matrix),
        "matrix": [entry.to_dict() for entry in matrix],
    }
    print(_json(payload))
    return 0


def cmd_judge_benchmark(args: argparse.Namespace) -> int:
    cases = load_benchmark_cases(args.benchmark)
    result = run_benchmark(cases)
    print(_json(result))
    metrics = result["metrics"]
    return 0 if metrics["false_positive"] == 0 and metrics["false_negative"] == 0 else 1


def cmd_normalize_tool_output(args: argparse.Namespace) -> int:
    adapter = _adapter_for_tool(args.tool)
    results = adapter.parse_file(args.input, run_id=args.run_id, target_id=args.target_id, version=args.version)
    print(_json([result.to_dict() for result in results]))
    return 0


def cmd_mutate(args: argparse.Namespace) -> int:
    testcases = load_testcases(args.testcases)
    selected = [case for case in testcases if case.id == args.testcase_id] if args.testcase_id else testcases
    engine = MutationEngine(strategies=args.strategy or None)
    candidates = []
    for case in selected:
        candidates.extend(engine.mutate(case, variables=dict(args.var or [])))
    if args.db:
        store = SQLiteStore(args.db)
        store.initialize()
        for candidate in candidates:
            store.insert_mutation(candidate.to_record())
    print(_json({"stats": mutation_stats(candidates), "mutations": [candidate.to_dict() for candidate in candidates]}))
    return 0


def cmd_adaptive_plan(args: argparse.Namespace) -> int:
    testcases = load_testcases(args.testcases)
    testcase_by_id = {case.id: case for case in testcases}
    results = PyRITAdapter().parse_file(args.input, run_id=args.run_id, target_id=args.target_id, version=args.version)
    planner = AdaptivePlanner()
    store = SQLiteStore(args.db) if args.db else None
    if store is not None:
        store.initialize()
    plans = []
    for result in results:
        testcase = testcase_by_id.get(result.testcase_id) if result.testcase_id else None
        if testcase is None:
            continue
        plan = planner.plan_from_result(result, testcase)
        plans.append(plan)
        if store is not None:
            for mutation in plan.mutations:
                store.insert_mutation(mutation.to_record())
    print(_json({"plans": [plan.to_dict() for plan in plans]}))
    return 0


def cmd_adaptive_run(args: argparse.Namespace) -> int:
    testcases = load_testcases(args.testcases)
    engine = PolicyEngine.from_yaml(args.scope)
    store = SQLiteStore(args.db)
    result = asyncio.run(
        run_adaptive_pipeline(engine, testcases, store, args.input, target_kind=args.target)
    )
    print(_json(result))
    return 0


def _adapter_for_tool(tool: str):
    if tool == "promptfoo":
        return PromptfooAdapter()
    if tool == "garak":
        return GarakAdapter()
    if tool == "pyrit":
        return PyRITAdapter()
    raise ValueError(f"unsupported tool: {tool}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm-bugbounty",
        description="Authorized LLM security testing automation pipeline",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="Check local runtime and optional tools")
    doctor.add_argument("--tools", type=Path, default=DEFAULT_TOOLS)
    doctor.add_argument("--json", action="store_true", help="Print machine-readable doctor output")
    doctor.add_argument("--write-lock", action="store_true", help="Write tool_versions.lock.yaml")
    doctor.add_argument("--lockfile", type=Path, default=Path("tool_versions.lock.yaml"))
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

    coverage = sub.add_parser("coverage", help="Show testcase coverage for a target profile")
    coverage.add_argument("--scope", type=Path, default=DEFAULT_SCOPE)
    coverage.add_argument("--testcases", type=Path, default=DEFAULT_TESTCASES)
    coverage.add_argument("--target", choices=["fake-llm", "fake-agent", "fake-rag"], default="fake-llm")
    coverage.set_defaults(func=cmd_coverage)

    judge_benchmark = sub.add_parser("judge-benchmark", help="Run judge benchmark fixtures")
    judge_benchmark.add_argument("--benchmark", type=Path, default=DEFAULT_JUDGE_BENCHMARK)
    judge_benchmark.set_defaults(func=cmd_judge_benchmark)

    normalize = sub.add_parser("normalize-tool-output", help="Normalize external LLM tool output")
    normalize.add_argument("--tool", choices=["promptfoo", "garak", "pyrit"], required=True)
    normalize.add_argument("--input", type=Path, required=True)
    normalize.add_argument("--run-id", default="run_fixture")
    normalize.add_argument("--target-id", default="target_fixture")
    normalize.add_argument("--version")
    normalize.set_defaults(func=cmd_normalize_tool_output)

    mutate = sub.add_parser("mutate", help="Generate prompt mutations")
    mutate.add_argument("--testcases", type=Path, default=DEFAULT_TESTCASES)
    mutate.add_argument("--testcase-id")
    mutate.add_argument("--strategy", action="append", choices=["identity", "markdown_wrap", "json_wrap", "roleplay", "multi_turn_split"])
    mutate.add_argument("--var", action="append", nargs=2, metavar=("KEY", "VALUE"))
    mutate.add_argument("--db", type=Path)
    mutate.set_defaults(func=cmd_mutate)

    adaptive_plan = sub.add_parser(
        "adaptive-plan",
        help="Generate adaptive mutation plans from PyRIT adaptive redteam results",
    )
    adaptive_plan.add_argument("--input", type=Path, required=True)
    adaptive_plan.add_argument("--testcases", type=Path, default=DEFAULT_TESTCASES)
    adaptive_plan.add_argument("--run-id", default="run_fixture")
    adaptive_plan.add_argument("--target-id", default="target_fixture")
    adaptive_plan.add_argument("--version")
    adaptive_plan.add_argument("--db", type=Path)
    adaptive_plan.set_defaults(func=cmd_adaptive_plan)

    adaptive_run = sub.add_parser(
        "adaptive-run",
        help="Execute PyRIT-informed adaptive mutations through the Executor/Judge/Reproducer pipeline",
    )
    adaptive_run.add_argument("--scope", type=Path, default=DEFAULT_SCOPE)
    adaptive_run.add_argument("--testcases", type=Path, default=DEFAULT_TESTCASES)
    adaptive_run.add_argument("--input", type=Path, required=True)
    adaptive_run.add_argument("--db", type=Path, default=Path("runs/adaptive.sqlite"))
    adaptive_run.add_argument("--target", choices=["fake-llm", "fake-agent", "fake-rag"], default="fake-llm")
    adaptive_run.set_defaults(func=cmd_adaptive_run)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
