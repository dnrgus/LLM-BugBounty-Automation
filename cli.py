from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
from pathlib import Path

import yaml

from adapters.llm.garak import GarakAdapter
from adapters.llm.promptfoo import PromptfooAdapter
from adapters.llm.pyrit import PyRITAdapter
from adapters.scanner.dalfox import DalfoxAdapter
from adapters.scanner.nuclei import NucleiAdapter
from adapters.secrets.trufflehog import TruffleHogAdapter
from attacks.adaptive import AdaptivePlanner
from attacks.mutation import MutationEngine, mutation_stats
from benchmarks.calibration import compute_confidence_calibration_across
from benchmarks.dataset import compare_to_baseline, load_dataset, run_dataset, write_baseline
from benchmarks.ground_truth import load_ground_truth_corpus
from benchmarks.matcher import match_findings_to_ground_truth
from benchmarks.metrics import aggregate_accuracy_metrics
from core.budget import AttackBudget
from core.cancel import CancellationToken
from core.contract import execution_environment, file_sha256
from core.fingerprint import build_environment_fingerprint
from core.models import Run
from core.orchestrator import (
    run_adaptive_pipeline,
    run_full_pipeline,
    run_hybrid_scan_pipeline,
    run_live_scan_pipeline,
    run_profile_target,
    run_reproduce_finding,
    run_sample_pipeline,
)
from core.profile import load_profile
from core.tool_doctor import check_tools, write_tool_lock
from executor.runner import Executor
from findings.dedup import cluster_findings
from findings.report import write_cluster_report
from hybrid.correlate import correlate_source_and_live
from judges.benchmark import load_benchmark_cases, run_benchmark
from judges.ensemble import JudgeEnsemble
from judges.semantic import load_semantic_judge_config
from live.auto_profile import auto_profile_candidates
from live.classify import classify_items
from live.discovery import discover_target
from packs.runner import run_selected_packs
from packs.selector import select_packs
from recon.pipeline import build_asset_map
from scenario.executor import run_scenario
from scenario.finding import promote_scenario_result
from scenario.loader import load_scenarios
from source.audit import audit_source, collect_source_items
from core.scan_context import AuthContext, ScanContext
from scope.auto import build_auto_scope
from scope.policy import PolicyEngine
from tools.runner import ExternalScanOptions
from storage.sqlite import SQLiteStore
from targets.factory import create_target
from testcase.coverage import build_coverage_matrix, coverage_summary
from testcase.loader import load_testcases
from testcase.selector import select_executable_testcases
from validation.auth_contexts import load_auth_contexts
from validation.workflow import (
    build_scan_artifact,
    is_replayable_validation_finding,
    load_scan_artifact,
    reproduce_validation_finding,
    run_validate,
    write_artifact,
    write_validation_report,
)


DEFAULT_SCOPE = Path("config/scope.example.yaml")
DEFAULT_TESTCASES = Path("testcase/suites/basic.yaml")
DEFAULT_SCENARIOS = Path("scenario/suites/basic.yaml")
DEFAULT_JUDGE_BENCHMARK = Path("benchmarks/judge/baseline.json")
DEFAULT_GROUND_TRUTH_CORPUS = Path("benchmarks/corpus")
DEFAULT_TOOLS = Path("config/tools.yaml")
DEFAULT_PIPELINE_CONFIG = Path("config/pipeline.yaml")
DEFAULT_FIXTURES = Path("tests/fixtures/tools")


def _json(data: object) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


# Human-readable purpose per tool, keyed by tool name with a category
# fallback, for `bugbounty tools` / `doctor` (§16, §18). Purely cosmetic:
# the source of truth for what is enabled stays config/tools.yaml.
_TOOL_PURPOSE = {
    "nuclei": "Dynamic / DAST",
    "dalfox": "XSS",
    "semgrep": "Static analysis",
    "promptfoo": "LLM red team",
    "garak": "LLM scanner",
    "pyrit": "LLM red team",
    "trufflehog": "Secret scan",
    "subfinder": "Subdomain recon",
    "httpx": "HTTP probe",
    "katana": "Crawl / discovery",
    "ffuf": "Fuzzing / discovery",
}
_CATEGORY_PURPOSE = {
    "web_scanner": "Dynamic scan",
    "static_analysis": "Static analysis",
    "llm_redteam": "LLM red team",
    "llm_scanner": "LLM scanner",
    "secret_scanner": "Secret scan",
    "recon": "Recon",
    "discovery": "Discovery",
}


def _tool_purpose(tool: dict[str, object]) -> str:
    name = str(tool.get("name", ""))
    if name in _TOOL_PURPOSE:
        return _TOOL_PURPOSE[name]
    return _CATEGORY_PURPOSE.get(str(tool.get("category") or ""), str(tool.get("category") or ""))


def cmd_doctor(args: argparse.Namespace) -> int:
    snapshot = check_tools(args.tools)
    if args.write_lock:
        write_tool_lock(snapshot, args.lockfile)
    if args.json:
        print(_json(snapshot))
        return 0
    print("BugBounty Environment Check")
    print()
    print(f"[OK] Python {snapshot['python']}")
    print(f"[OK] Platform {snapshot['platform']}")
    for tool in snapshot["tools"]:
        label = "OK" if tool["available"] else "WARN"
        detail = tool["version"] or tool["path"] or "not installed"
        print(f"[{label}] {tool['name']} {detail}")
    # The internal offline pipeline (testcase suites, judge, reproducer,
    # report) needs no external tool, so core readiness never depends on
    # them (§17 critical vs optional). External scanners are optional
    # capabilities that degrade gracefully when missing.
    print()
    print("Core pipeline ready.")
    missing = [t["name"] for t in snapshot["tools"] if not t["available"]]
    if missing:
        print(f"Optional tools missing (capabilities degraded): {', '.join(missing)}")
    return 0


def cmd_tools(args: argparse.Namespace) -> int:
    snapshot = check_tools(args.tools)
    if args.json:
        print(_json(snapshot))
        return 0
    print(f"{'Tool':<15} {'Status':<11} Purpose")
    print(f"{'-' * 14:<15} {'-' * 10:<11} {'-' * 7}")
    for tool in snapshot["tools"]:
        status = "Ready" if tool["available"] else "Missing"
        print(f"{tool['name']:<15} {status:<11} {_tool_purpose(tool)}")
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

    # P3.4-2: Ctrl-C sets the cancellation token instead of raising
    # KeyboardInterrupt -- run_sample_pipeline checks it cooperatively
    # between testcases and marks the run cancelled (resumable later)
    # rather than dying mid-write with a stack trace.
    cancellation = CancellationToken()
    previous_handler = signal.signal(signal.SIGINT, lambda *_: cancellation.cancel("SIGINT (Ctrl-C)"))
    try:
        result = asyncio.run(
            run_sample_pipeline(
                engine, testcases, store, target_kind=args.target, target_config=args.target_config,
                resume_run_id=args.resume_run_id, cancellation=cancellation,
                semantic_judge=load_semantic_judge_config(args.semantic_judge_config) if args.semantic_judge_config else None,
            )
        )
    finally:
        signal.signal(signal.SIGINT, previous_handler)
    print(_json(result))
    return 130 if result["cancelled"] else 0


def cmd_coverage(args: argparse.Namespace) -> int:
    testcases = load_testcases(args.testcases)
    target = create_target(args.target, args.target_config)
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


def cmd_quality_gate(args: argparse.Namespace) -> int:
    """P4.4-D (roadmap v4.4.0 Accuracy & Benchmark): runs SOURCE MODE
    against every fixture in the ground-truth corpus, scores the
    result (P4.4-C), and fails (non-zero exit) if the aggregated
    precision/recall drop below the given thresholds -- mirrors
    cmd_judge_benchmark's own "print the report, then gate on it"
    shape.
    """
    corpus = load_ground_truth_corpus(args.corpus)
    if not corpus:
        print(_json({"error": f"no *.ground_truth.yaml files found under {args.corpus}"}))
        return 1

    per_fixture: list[dict[str, object]] = []
    all_metrics = []
    all_results = []
    for entry in corpus:
        _, items = collect_source_items(entry.fixture_path)
        result = match_findings_to_ground_truth(items, entry.findings)
        per_fixture.append({"fixture_path": entry.fixture_path, **result.to_dict()})
        all_metrics.append(result.metrics)
        all_results.append(result)

    aggregated = aggregate_accuracy_metrics(all_metrics)
    # P4.4-E: reported alongside the gate, never gated on itself -- a
    # corpus this small doesn't yet give a statistically meaningful
    # confidence signal, but the number is worth watching as the
    # corpus grows.
    calibration = compute_confidence_calibration_across(all_results)
    payload = {"fixtures": per_fixture, "aggregated": aggregated.to_dict(), "confidence_calibration": calibration.to_dict()}
    print(_json(payload))

    if aggregated.recall < args.min_recall:
        return 1
    if aggregated.precision < args.min_precision:
        return 1
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    """P4.7 WP-07: run the fixed benchmark dataset; with --baseline, exit 1
    on any per-target regression (fewer TP, more FP/FN, or a target that
    stopped running cleanly)."""
    report = run_dataset(load_dataset(args.manifest), timeout_s=args.timeout)
    if args.baseline:
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        report["regressions"] = compare_to_baseline(report, baseline)
    if args.write_baseline:
        report["baseline_written"] = str(write_baseline(report, args.write_baseline))
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(_json(report), encoding="utf-8")
    print(_json(report))
    return 1 if report.get("regressions") else 0


def cmd_release_check(args: argparse.Namespace) -> int:
    """P5.0 WP-10: the v5.0.0 release gate (plan 8.3) as an offline checklist."""
    from core.release_check import run_release_check

    result = run_release_check(only=args.gate)
    print(_json(result))
    return 0 if result["passed"] else 1


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
        run_adaptive_pipeline(
            engine, testcases, store, args.input, target_kind=args.target, target_config=args.target_config
        )
    )
    print(_json(result))
    return 0


def cmd_reproduce(args: argparse.Namespace) -> int:
    policy = PolicyEngine.from_yaml(args.scope)
    store = SQLiteStore(args.db)
    # P4.5 WP-03: a `validate`-produced object access finding replays its
    # own stored spec instead of a testcase.
    finding = store.get_finding(args.finding_id)
    if finding is not None and is_replayable_validation_finding(finding):
        contexts = load_auth_contexts(args.auth_contexts) if args.auth_contexts else None
        environment = execution_environment(
            validator_type="object_access", attempts=args.attempts, scope_sha256=file_sha256(args.scope),
            auth_contexts_sha256=file_sha256(args.auth_contexts),
        )
        result = asyncio.run(
            reproduce_validation_finding(finding, policy, store, contexts, attempts=args.attempts, environment=environment)
        )
        result["environment"] = environment
        print(_json(result))
        return 0
    testcases = load_testcases(args.testcases)
    result = asyncio.run(
        run_reproduce_finding(
            policy,
            testcases,
            store,
            args.finding_id,
            target_kind=args.target,
            target_config=args.target_config,
            minimize=args.minimize,
        )
    )
    # P5.0 WP-09: every reproduction records its execution conditions.
    result["environment"] = execution_environment(
        target_kind=args.target, target_config=str(args.target_config) if args.target_config else None,
        target_config_sha256=file_sha256(args.target_config), testcases_sha256=file_sha256(args.testcases),
        scope_sha256=file_sha256(args.scope), minimize=args.minimize,
    )
    print(_json(result))
    return 0


def cmd_profile(args: argparse.Namespace) -> int:
    policy = PolicyEngine.from_yaml(args.scope)
    store = SQLiteStore(args.db)
    result = asyncio.run(
        run_profile_target(
            policy,
            store,
            target_kind=args.target,
            target_config=args.target_config,
            probe=not args.no_probe,
        )
    )
    print(_json(result))
    return 0


def cmd_discover(args: argparse.Namespace) -> int:
    policy = PolicyEngine.from_yaml(args.scope)
    result = asyncio.run(discover_target(args.url, policy, max_pages=args.max_pages))
    payload = result.to_dict()

    select_packs_requested = args.select_packs or args.run_packs
    if args.classify or args.auto_profile or select_packs_requested:
        candidates = classify_items(result.items)
        payload["classification"] = [candidate.to_dict() for candidate in candidates]
        if args.auto_profile:
            store = SQLiteStore(args.db)
            profiles = asyncio.run(auto_profile_candidates(candidates, policy, store))
            payload["auto_profile"] = [profile_result.to_dict() for profile_result in profiles]
        if select_packs_requested:
            budget = AttackBudget(max_requests=args.pack_budget_requests) if args.pack_budget_requests else None
            target_kinds = {candidate.kind for candidate in candidates}
            selections = select_packs(target_kinds, policy, budget=budget)
            payload["pack_selection"] = [selection.to_dict() for selection in selections]

            if args.run_packs:
                testcases = load_testcases(args.testcases)
                store = SQLiteStore(args.db)
                external_scan_inputs: dict[str, Path | str] = {}
                if args.nuclei_results:
                    external_scan_inputs["nuclei"] = args.nuclei_results
                if args.dalfox_results:
                    external_scan_inputs["dalfox"] = args.dalfox_results
                if args.trufflehog_results:
                    external_scan_inputs["trufflehog"] = args.trufflehog_results
                pack_runs = asyncio.run(
                    run_selected_packs(
                        selections, testcases, policy, store,
                        target_kind=args.pack_target, target_config=args.pack_target_config,
                        external_scan_inputs=external_scan_inputs,
                        live_target_url=args.url,
                    )
                )
                payload["pack_runs"] = [pack_run.to_dict() for pack_run in pack_runs]

    print(_json(payload))
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    result = audit_source(args.path, max_files=args.max_files)
    print(_json(result))
    return 0


def cmd_correlate(args: argparse.Namespace) -> int:
    policy = PolicyEngine.from_yaml(args.scope)
    live_result = asyncio.run(discover_target(args.url, policy, max_pages=args.max_pages))
    result = correlate_source_and_live(args.source, live_result, max_files=args.max_files)
    print(_json(result.to_dict()))
    return 0


async def _run_scenarios(args: argparse.Namespace) -> dict[str, object]:
    policy = PolicyEngine.from_yaml(args.scope)
    store = SQLiteStore(args.db)
    store.initialize()
    scenarios = load_scenarios(args.scenarios)
    target = create_target(args.target, args.target_config)
    target_metadata = await target.metadata()
    executor = Executor(policy=policy, target=target, store=store, target_id=target_metadata.id)
    judges = JudgeEnsemble.default()

    results = []
    all_findings = []
    for scenario in scenarios:
        run = Run(target_id=target_metadata.id, policy_hash=policy.policy_hash, fingerprint=f"scenario:{scenario.id}")
        store.insert_run(run)
        result = await run_scenario(scenario, run, executor, judges, store, target_url=target_metadata.base_url)
        # P3.1-2: promote every flagged step into a first-class, individually
        # reproducible Finding (see scenario/finding.py) instead of leaving
        # scenario results outside the normal Finding/Evidence lifecycle.
        findings = promote_scenario_result(scenario, result, store)
        all_findings.extend(findings)
        payload = result.to_dict()
        payload["findings"] = [
            {"finding_id": finding.id, "step_id": finding.reproduction_spec["step_id"], "category": finding.category}
            for finding in findings
        ]
        results.append(payload)

    report_path = None
    if all_findings:
        clusters = cluster_findings(all_findings)
        combined_run = Run(target_id=target_metadata.id, policy_hash=policy.policy_hash, fingerprint="scenario_combined")
        report_path = str(write_cluster_report(Path("reports/shareable"), combined_run, clusters))
        cluster_payload = [cluster.to_dict() for cluster in clusters]
    else:
        cluster_payload = []

    return {
        "scenarios": results,
        "finding_count": len(all_findings),
        "clusters": cluster_payload,
        "report": report_path,
    }


def cmd_run_scenario(args: argparse.Namespace) -> int:
    print(_json(asyncio.run(_run_scenarios(args))))
    return 0


def cmd_recon(args: argparse.Namespace) -> int:
    policy = PolicyEngine.from_yaml(args.scope)
    store = SQLiteStore(args.db)
    result = build_asset_map(
        policy,
        store,
        run_id=args.run_id,
        target_id=args.target_id,
        subfinder_input=args.subfinder_input,
        httpx_input=args.httpx_input,
        katana_input=args.katana_input,
        ffuf_input=args.ffuf_input,
    )
    print(_json(result))
    return 0


def _resolve_scan_policy(args: argparse.Namespace) -> PolicyEngine:
    """WP-04: pick the scope for a scan.

    Explicit --scope always wins. Otherwise, a URL target on a
    loopback/private host gets a conservative auto-scope so a local lab
    (e.g. Juice Shop on 127.0.0.1) needs no hand-written YAML; a public
    host raises (ScopeNotAutoAllowedError -> exit 3) demanding an explicit
    --scope, so usability never invents authorization (§4, §32). With no
    URL (the fixture-driven --profile path) the historical DEFAULT_SCOPE is
    used, preserving existing behavior.
    """
    if args.scope is not None:
        return PolicyEngine.from_yaml(args.scope)
    if args.url:
        config = build_auto_scope(args.url)
        print(
            f"[scope] no --scope given; using auto-scope for local target {args.url}",
            file=sys.stderr,
        )
        return PolicyEngine(config)
    return PolicyEngine.from_yaml(DEFAULT_SCOPE)


def _auth_from_args(args: argparse.Namespace) -> AuthContext:
    """Collect --auth-token / --header (and the BUGBOUNTY_AUTH_TOKEN env
    fallback) into one AuthContext reused by every scanner (§19)."""
    headers: dict[str, str] = {}
    for raw in getattr(args, "header", None) or []:
        name, sep, value = raw.partition(":")
        if not sep:
            raise ValueError(f"--header must be 'Name: value', got {raw!r}")
        headers[name.strip()] = value.strip()
    token = getattr(args, "auth_token", None) or os.environ.get("BUGBOUNTY_AUTH_TOKEN")
    return AuthContext(token=token, headers=headers)


def _scan_output_dir(args: argparse.Namespace) -> Path:
    """Where a scan's results directory goes (§14). --output wins; otherwise
    a timestamped folder under ./BugBounty-Results derived from the target."""
    explicit = getattr(args, "output", None)
    if explicit is not None:
        return Path(explicit)
    return ScanContext.create(target=args.url, source_path=args.source).output_dir


def _scan_options_from_args(args: argparse.Namespace) -> ExternalScanOptions:
    auth = _auth_from_args(args)
    return ExternalScanOptions(
        auth_headers=auth.as_request_headers(),
        tool_timeout=float(getattr(args, "tool_timeout", 600.0)),
        nuclei_dast=getattr(args, "nuclei_dast", False),
        full_templates=getattr(args, "full_templates", False),
    )


def cmd_scan(args: argparse.Namespace) -> int:
    if args.source and not args.url:
        # P4.5 WP-03: SOURCE-only `scan --source <path>` writes the common
        # scan artifact (inventory + candidates) that `validate` reads.
        artifact = build_scan_artifact(args.source, captured_requests=args.captured_requests)
        artifact_path = write_artifact(args.artifact or Path("runs/artifacts") / f"{artifact['id']}.json", artifact)
        inventory = artifact["endpoint_inventory"]
        print(
            _json(
                {
                    "mode": "source",
                    "artifact": str(artifact_path),
                    "artifact_id": artifact["id"],
                    "candidates": len(artifact["items"]),
                    "endpoints": len(inventory),
                    "endpoints_by_risk": _count_by(inventory, "risk"),
                }
            )
        )
        return 0

    profile = load_profile(args.profile, args.pipeline_config)
    policy = _resolve_scan_policy(args)
    testcases = load_testcases(args.testcases)
    store = SQLiteStore(args.db)

    if args.url and args.source:
        # P3.3-4: HYBRID MODE entry point -- SOURCE audit + LIVE discovery +
        # entity resolution + validation planning + dynamic validation, in
        # one call.
        result = asyncio.run(
            run_hybrid_scan_pipeline(
                policy,
                testcases,
                store,
                profile,
                args.url,
                args.source,
                max_pages=args.max_pages,
                pack_target=args.pack_target,
                pack_target_config=args.pack_target_config,
                auth_context_available=args.auth_context,
                output_dir=_scan_output_dir(args),
            )
        )
        print(_json(result))
        if result.get("results"):
            from reporting.results import render_console_summary

            print(render_console_summary(result["results"]), file=sys.stderr)
        return 0

    if args.url:
        # P3.1-1: LIVE MODE entry point -- discover/classify/select-packs/run-packs
        # against a real URL, instead of the fixture-driven --profile path below.
        result = asyncio.run(
            run_live_scan_pipeline(
                policy,
                testcases,
                store,
                profile,
                args.url,
                max_pages=args.max_pages,
                auto_profile=args.auto_profile,
                pack_target=args.pack_target,
                pack_target_config=args.pack_target_config,
                pack_budget_requests=args.pack_budget_requests,
                external_scan_inputs={
                    "nuclei": args.nuclei_results,
                    "dalfox": args.dalfox_results,
                    "trufflehog": args.trufflehog_results,
                },
                scan_options=_scan_options_from_args(args),
                output_dir=_scan_output_dir(args),
                progress=not getattr(args, "quiet", False),
            )
        )
        print(_json(result))
        if result.get("results"):
            from reporting.results import render_console_summary

            print(render_console_summary(result["results"]), file=sys.stderr)
        return 0

    recon_inputs = {
        "subfinder": args.subfinder_input,
        "httpx": args.httpx_input,
        "katana": args.katana_input,
        "ffuf": args.ffuf_input,
    }
    external_inputs = {
        "nuclei": args.nuclei_input,
        "dalfox": args.dalfox_input,
        "trufflehog": args.trufflehog_input,
    }
    result = asyncio.run(
        run_full_pipeline(
            policy,
            testcases,
            store,
            profile,
            recon_inputs=recon_inputs,
            pyrit_input=args.pyrit_input,
            external_inputs=external_inputs,
        )
    )
    print(_json(result))
    return 0


def _count_by(entries: object, key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries:  # type: ignore[union-attr]
        counts[str(entry[key])] = counts.get(str(entry[key]), 0) + 1
    return counts


def cmd_validate(args: argparse.Namespace) -> int:
    artifact = load_scan_artifact(args.artifact)
    policy = PolicyEngine.from_yaml(args.scope)
    store = SQLiteStore(args.db)
    contexts = load_auth_contexts(args.auth_contexts) if args.auth_contexts else None
    result = asyncio.run(run_validate(artifact, args.base_url, policy, store, auth_contexts=contexts, key_fields=args.key_field))
    print(_json(result))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    store = SQLiteStore(args.db)
    store.initialize()
    print(_json(write_validation_report(store, args.run_id, args.out)))
    return 0


def _adapter_for_tool(tool: str):
    if tool == "promptfoo":
        return PromptfooAdapter()
    if tool == "garak":
        return GarakAdapter()
    if tool == "pyrit":
        return PyRITAdapter()
    if tool == "nuclei":
        return NucleiAdapter()
    if tool == "dalfox":
        return DalfoxAdapter()
    if tool == "trufflehog":
        return TruffleHogAdapter()
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

    tools_cmd = sub.add_parser("tools", help="List supported external tools and their status/purpose")
    tools_cmd.add_argument("--tools", type=Path, default=DEFAULT_TOOLS)
    tools_cmd.add_argument("--json", action="store_true", help="Print machine-readable tool status")
    tools_cmd.set_defaults(func=cmd_tools)

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
    sample.add_argument("--target", choices=["fake-llm", "fake-agent", "fake-rag", "openai"], default="fake-llm")
    sample.add_argument(
        "--target-config",
        type=Path,
        help="YAML target config (see config/targets/*.example.yaml); overrides --target",
    )
    sample.add_argument(
        "--resume-run-id", default=None,
        help="P3.4-1: reuse this run_id and skip its already-completed testcases (from a prior "
        "invocation against the same --db) instead of a fresh run. Rejects the call if --testcases/"
        "--target/etc. changed since that run_id was started.",
    )
    sample.add_argument(
        "--semantic-judge-config", type=Path, default=None,
        help="P4.6: opt-in secondary semantic judge (see config/semantic_judge.example.yaml); conflicts or low "
        "confidence become needs_review, never confirmed",
    )
    sample.set_defaults(func=cmd_sample_run)

    coverage = sub.add_parser("coverage", help="Show testcase coverage for a target profile")
    coverage.add_argument("--scope", type=Path, default=DEFAULT_SCOPE)
    coverage.add_argument("--testcases", type=Path, default=DEFAULT_TESTCASES)
    coverage.add_argument("--target", choices=["fake-llm", "fake-agent", "fake-rag", "openai"], default="fake-llm")
    coverage.add_argument("--target-config", type=Path, help="YAML target config; overrides --target")
    coverage.set_defaults(func=cmd_coverage)

    profile_cmd = sub.add_parser(
        "profile",
        help="Probe a target's capabilities (declared config + observed multi-turn behavior)",
    )
    profile_cmd.add_argument("--scope", type=Path, default=DEFAULT_SCOPE)
    profile_cmd.add_argument("--db", type=Path, default=Path("runs/profile.sqlite"))
    profile_cmd.add_argument("--target", choices=["fake-llm", "fake-agent", "fake-rag", "openai"], default="fake-llm")
    profile_cmd.add_argument("--target-config", type=Path, help="YAML target config; overrides --target")
    profile_cmd.add_argument(
        "--no-probe",
        action="store_true",
        help="Skip active probing; report only the target's declared capabilities",
    )
    profile_cmd.set_defaults(func=cmd_profile)

    reproduce = sub.add_parser(
        "reproduce",
        help="Re-run reproduction for a stored finding against a live target, optionally minimizing a PoC",
    )
    reproduce.add_argument("finding_id")
    reproduce.add_argument("--scope", type=Path, default=DEFAULT_SCOPE)
    reproduce.add_argument("--testcases", type=Path, default=DEFAULT_TESTCASES)
    reproduce.add_argument("--db", type=Path, default=Path("runs/sample.sqlite"))
    reproduce.add_argument("--target", choices=["fake-llm", "fake-agent", "fake-rag", "openai"], default="fake-llm")
    reproduce.add_argument("--target-config", type=Path, help="YAML target config; overrides --target")
    reproduce.add_argument(
        "--minimize",
        action="store_true",
        help="If the finding still reproduces, also generate a minimal PoC",
    )
    reproduce.add_argument(
        "--auth-contexts", type=Path, default=None,
        help="object access findings from `validate`: tester account YAML (see config/auth_contexts.example.yaml)",
    )
    reproduce.add_argument("--attempts", type=int, default=3, help="object access findings: number of re-runs")
    reproduce.set_defaults(func=cmd_reproduce)

    validate_cmd = sub.add_parser(
        "validate",
        help="Run safe validators over a `scan --source` artifact (scope + method policy gate, object access "
        "comparison with tester-owned accounts)",
    )
    validate_cmd.add_argument("--artifact", type=Path, required=True)
    validate_cmd.add_argument("--base-url", required=True, help="Base URL of the authorized target")
    validate_cmd.add_argument("--scope", type=Path, default=DEFAULT_SCOPE)
    validate_cmd.add_argument("--db", type=Path, default=Path("runs/validate.sqlite"))
    validate_cmd.add_argument("--auth-contexts", type=Path, default=None)
    validate_cmd.add_argument("--key-field", action="append", default=None, help="response field compared (as a hash)")
    validate_cmd.set_defaults(func=cmd_validate)

    report_cmd = sub.add_parser("report", help="Write per-finding reports for a `validate` run")
    report_cmd.add_argument("--run-id", required=True)
    report_cmd.add_argument("--db", type=Path, default=Path("runs/validate.sqlite"))
    report_cmd.add_argument("--out", type=Path, default=Path("reports/validation"))
    report_cmd.set_defaults(func=cmd_report)

    judge_benchmark = sub.add_parser("judge-benchmark", help="Run judge benchmark fixtures")
    judge_benchmark.add_argument("--benchmark", type=Path, default=DEFAULT_JUDGE_BENCHMARK)
    judge_benchmark.set_defaults(func=cmd_judge_benchmark)

    quality_gate = sub.add_parser("quality-gate", help="Score SOURCE MODE against the ground-truth corpus")
    quality_gate.add_argument("--corpus", type=Path, default=DEFAULT_GROUND_TRUTH_CORPUS)
    quality_gate.add_argument("--min-recall", type=float, default=0.85)
    quality_gate.add_argument("--min-precision", type=float, default=0.85)
    quality_gate.set_defaults(func=cmd_quality_gate)

    benchmark_cmd = sub.add_parser(
        "benchmark", help="Run the benchmark dataset (TP/FP/FN, miss reasons, stability) and compare to a baseline"
    )
    benchmark_cmd.add_argument("--manifest", type=Path, default=Path("benchmarks/datasets/manifest.yaml"))
    benchmark_cmd.add_argument("--timeout", type=float, default=60.0, help="per-target timeout in seconds")
    benchmark_cmd.add_argument("--baseline", type=Path, default=None, help="fail (exit 1) on regression vs this baseline")
    benchmark_cmd.add_argument("--write-baseline", type=Path, default=None)
    benchmark_cmd.add_argument("--out", type=Path, default=None, help="also write the full report JSON here")
    benchmark_cmd.set_defaults(func=cmd_benchmark)

    release_check = sub.add_parser(
        "release-check", help="Run the v5.0.0 release gate checklist offline (G1-G10); exit 1 if any gate fails"
    )
    release_check.add_argument("--gate", action="append", default=None, help="run only this gate id (repeatable), e.g. G5")
    release_check.set_defaults(func=cmd_release_check)

    normalize = sub.add_parser("normalize-tool-output", help="Normalize external LLM tool output")
    normalize.add_argument(
        "--tool",
        choices=["promptfoo", "garak", "pyrit", "nuclei", "dalfox", "trufflehog"],
        required=True,
    )
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
    adaptive_run.add_argument("--target", choices=["fake-llm", "fake-agent", "fake-rag", "openai"], default="fake-llm")
    adaptive_run.add_argument("--target-config", type=Path, help="YAML target config; overrides --target")
    adaptive_run.set_defaults(func=cmd_adaptive_run)

    recon = sub.add_parser(
        "recon",
        help="Build a scope-revalidated asset map from Subfinder/httpx/Katana/ffuf output",
    )
    recon.add_argument("--scope", type=Path, default=DEFAULT_SCOPE)
    recon.add_argument("--run-id", default="run_fixture")
    recon.add_argument("--target-id", default="target_fixture")
    recon.add_argument("--db", type=Path, default=Path("runs/recon.sqlite"))
    recon.add_argument("--subfinder-input", type=Path)
    recon.add_argument("--httpx-input", type=Path)
    recon.add_argument("--katana-input", type=Path)
    recon.add_argument("--ffuf-input", type=Path)
    recon.set_defaults(func=cmd_recon)

    audit = sub.add_parser(
        "audit",
        help="SOURCE MODE: statically analyze a source tree (routes/inputs/sinks/secrets/LLM integration)",
    )
    audit.add_argument("path", type=Path)
    audit.add_argument("--max-files", type=int, default=2000)
    audit.set_defaults(func=cmd_audit)

    correlate = sub.add_parser(
        "correlate",
        help="U8 HYBRID MODE: correlate SOURCE static analysis with a LIVE discovery crawl of the same target "
        "(source-detected routes also seen live get a confidence boost and provenance from both sides)",
    )
    correlate.add_argument("source", type=Path)
    correlate.add_argument("url")
    correlate.add_argument("--scope", type=Path, default=DEFAULT_SCOPE)
    correlate.add_argument("--max-pages", type=int, default=5)
    correlate.add_argument("--max-files", type=int, default=2000)
    correlate.set_defaults(func=cmd_correlate)

    run_scenario_cmd = sub.add_parser(
        "run-scenario",
        help="U9 Scenario Engine: run a multi-turn/cross-session Scenario suite against a target "
        "(runs alongside the normal `sample-run`/`scan` single-testcase path, not in place of it)",
    )
    run_scenario_cmd.add_argument("--scope", type=Path, default=DEFAULT_SCOPE)
    run_scenario_cmd.add_argument("--scenarios", type=Path, default=DEFAULT_SCENARIOS)
    run_scenario_cmd.add_argument("--db", type=Path, default=Path("runs/scenario.sqlite"))
    run_scenario_cmd.add_argument("--target", choices=["fake-llm", "fake-agent", "fake-rag", "openai"], default="fake-llm")
    run_scenario_cmd.add_argument(
        "--target-config", type=Path, default=None,
        help="Required for --target openai; ignored for the fake targets",
    )
    run_scenario_cmd.set_defaults(func=cmd_run_scenario)

    discover = sub.add_parser(
        "discover",
        help="LIVE MODE: passively crawl a URL (GET/HEAD only, no attack payloads) for candidate attack surface",
    )
    discover.add_argument("url")
    discover.add_argument("--scope", type=Path, default=DEFAULT_SCOPE)
    discover.add_argument("--max-pages", type=int, default=5)
    discover.add_argument(
        "--classify", action="store_true",
        help="U5 Auto Profiler: also classify discovered items into web/api/graphql/llm/rag/agent/websocket candidates",
    )
    discover.add_argument(
        "--auto-profile", action="store_true",
        help="U5 Auto Profiler: classify, then hand llm/api candidates to the Capability Probe for best-effort verification (implies --classify)",
    )
    discover.add_argument("--db", type=Path, default=Path("runs/discover.sqlite"))
    discover.add_argument(
        "--select-packs", action="store_true",
        help="U6 Pack Selector: classify, then decide which Attack Packs apply given policy and (optional) budget",
    )
    discover.add_argument(
        "--pack-budget-requests", type=int, default=None,
        help="Optional request budget ceiling used only for --select-packs' budget check",
    )
    discover.add_argument(
        "--run-packs", action="store_true",
        help="U7: actually run selected packs (implies --select-packs) -- testcase_suite packs run against --pack-target; "
        "external-tool packs (nuclei/dalfox/trufflehog) only run if you supply their results file",
    )
    discover.add_argument("--testcases", type=Path, default=DEFAULT_TESTCASES)
    discover.add_argument("--pack-target", choices=["fake-llm", "fake-agent", "fake-rag", "openai"], default=None)
    discover.add_argument("--pack-target-config", type=Path, default=None)
    discover.add_argument("--nuclei-results", type=Path, default=None)
    discover.add_argument("--dalfox-results", type=Path, default=None)
    discover.add_argument("--trufflehog-results", type=Path, default=None)
    discover.set_defaults(func=cmd_discover)

    scan = sub.add_parser(
        "scan",
        help="LIVE MODE: `scan <url>` discovers/classifies/selects/runs packs end-to-end (P3.1-1). "
        "HYBRID MODE: `scan <url> --source <path>` adds SOURCE audit + entity resolution + dynamic "
        "validation (P3.3-4). Without a url, runs the fixture-driven full orchestrator (scope -> "
        "recon -> classify -> scan -> judge -> reproduce -> dedup -> report) for a profile.",
    )
    scan.add_argument(
        "url", nargs="?", default=None,
        help="LIVE/HYBRID MODE: target URL to discover/classify/pack-select/pack-run. Omit to use "
        "the fixture-based --profile pipeline below.",
    )
    scan.add_argument(
        "--source", type=Path, default=None,
        help="HYBRID MODE: source tree to audit alongside the url (SOURCE + LIVE correlation and "
        "dynamic validation, P3.3-4). Without url: SOURCE-only scan that writes a scan artifact for "
        "`validate` (P4.5 WP-03).",
    )
    scan.add_argument("--artifact", type=Path, default=None, help="SOURCE-only scan: artifact output path")
    scan.add_argument(
        "--captured-requests", type=Path, default=None,
        help="SOURCE-only scan: HAR or JSON list of real requests; overrides inferred request shape",
    )
    scan.add_argument(
        "--auth-context", action="store_true",
        help="HYBRID MODE only: an authenticated session/account is available for testing, so "
        "endpoints with a detected auth guard aren't automatically downgraded to review_only",
    )
    scan.add_argument("--profile", choices=["quick", "llm", "agent", "rag", "web", "full"], default="quick")
    scan.add_argument("--pipeline-config", type=Path, default=DEFAULT_PIPELINE_CONFIG)
    scan.add_argument(
        "--scope", type=Path, default=None,
        help="Scope/policy YAML. Omit for a localhost/private URL to get a safe auto-scope; "
        "public URLs require this. With no URL (fixture --profile mode) defaults to the sample scope.",
    )
    scan.add_argument(
        "--auth-token", default=None,
        help="Bearer token sent as 'Authorization: Bearer ...' by every scanner. "
        "Falls back to the BUGBOUNTY_AUTH_TOKEN env var. Redacted in output/evidence.",
    )
    scan.add_argument(
        "--header", action="append", default=None, metavar="'Name: value'",
        help="Extra request header reused by every scanner; repeatable.",
    )
    scan.add_argument(
        "--tool-timeout", type=float, default=600.0,
        help="Per-tool subprocess timeout in seconds for live scanners (default 600).",
    )
    scan.add_argument(
        "--no-dast", dest="nuclei_dast", action="store_false",
        help="Disable nuclei DAST parameter fuzzing (on by default for live URL scans).",
    )
    scan.add_argument(
        "--full-templates", action="store_true",
        help="With DAST, also run the full nuclei template set (slower, broader) instead of "
        "only the fast fuzzing templates.",
    )
    scan.add_argument(
        "--output", "-o", type=Path, default=None,
        help="Results directory. Default: a timestamped folder under ./BugBounty-Results/.",
    )
    scan.add_argument(
        "--quiet", action="store_true", help="Suppress the [n/6] progress lines on stderr.",
    )
    scan.set_defaults(nuclei_dast=True)
    scan.add_argument("--testcases", type=Path, default=DEFAULT_TESTCASES)
    scan.add_argument("--db", type=Path, default=Path("runs/scan.sqlite"))
    scan.add_argument("--max-pages", type=int, default=5, help="LIVE/HYBRID MODE only: max pages for the discovery crawl")
    scan.add_argument(
        "--auto-profile", action="store_true",
        help="LIVE MODE only: verify classified llm/api candidates via the Capability Probe",
    )
    scan.add_argument("--pack-target", choices=["fake-llm", "fake-agent", "fake-rag", "openai"], default=None)
    scan.add_argument("--pack-target-config", type=Path, default=None)
    scan.add_argument("--pack-budget-requests", type=int, default=None)
    scan.add_argument("--nuclei-results", type=Path, default=None, help="LIVE MODE only: see `discover --nuclei-results`")
    scan.add_argument("--dalfox-results", type=Path, default=None, help="LIVE MODE only: see `discover --dalfox-results`")
    scan.add_argument("--trufflehog-results", type=Path, default=None, help="LIVE MODE only: see `discover --trufflehog-results`")
    scan.add_argument("--subfinder-input", type=Path, default=DEFAULT_FIXTURES / "subfinder-results.jsonl")
    scan.add_argument("--httpx-input", type=Path, default=DEFAULT_FIXTURES / "httpx-results.jsonl")
    scan.add_argument("--katana-input", type=Path, default=DEFAULT_FIXTURES / "katana-results.jsonl")
    scan.add_argument("--ffuf-input", type=Path, default=DEFAULT_FIXTURES / "ffuf-results.json")
    scan.add_argument("--nuclei-input", type=Path, default=DEFAULT_FIXTURES / "nuclei-results.jsonl")
    scan.add_argument("--dalfox-input", type=Path, default=DEFAULT_FIXTURES / "dalfox-results.json")
    scan.add_argument("--trufflehog-input", type=Path, default=DEFAULT_FIXTURES / "trufflehog-results.jsonl")
    scan.add_argument("--pyrit-input", type=Path, default=DEFAULT_FIXTURES / "pyrit-results.json")
    scan.set_defaults(func=cmd_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError, yaml.YAMLError) as exc:
        # P5.0 WP-09: input/config errors are exit code 3 with a JSON
        # error on stderr, never a traceback (core/contract.py EXIT_CODES).
        print(_json({"error": type(exc).__name__, "detail": str(exc)}), file=sys.stderr)
        return 3
