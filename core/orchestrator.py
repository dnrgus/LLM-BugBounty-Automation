from __future__ import annotations

from dataclasses import asdict, replace
from pathlib import Path

import httpx

from adapters.llm.pyrit import PyRITAdapter
from adapters.scanner.dalfox import DalfoxAdapter
from adapters.scanner.nuclei import NucleiAdapter
from adapters.secrets.trufflehog import TruffleHogAdapter
from attacks.adaptive import AdaptivePlanner
from attacks.mutation import MutationEngine
from core.budget import AttackBudget
from core.fingerprint import build_environment_fingerprint
from core.models import (
    Finding,
    FindingStatus,
    PromptRecord,
    RequestRecord,
    ResponseRecord,
    Run,
    StoredTestcase,
    Target,
    Trace,
    new_id,
)
from core.profile import PipelineProfile
from core.profiler import profile_target
from executor.runner import Executor
from findings.dedup import base_testcase_id, cluster_findings
from findings.report import write_cluster_report
from judges.ensemble import JudgeEnsemble
from live.auto_profile import auto_profile_candidates
from live.classify import classify_items
from live.discovery import discover_target
from packs.selector import select_packs
from recon.pipeline import build_asset_map
from reporting.evidence import write_evidence_bundle
from reporting.reporter import write_json_report, write_markdown_report
from reproduction.minimal_poc import minimize_poc
from reproduction.reproducer import Reproducer
from scenario.models import Scenario, ScenarioStep
from scenario.reproducer import reproduce_scenario_finding
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from targets.base import TargetMetadata
from targets.errors import TargetError
from targets.factory import create_target
from testcase.coverage import build_coverage_matrix, coverage_summary
from testcase.selector import select_executable_testcases
from testcase.schema import Testcase

_MAX_CONSECUTIVE_TARGET_ERRORS = 3


async def run_sample_pipeline(
    policy: PolicyEngine,
    testcases: list[Testcase],
    store: SQLiteStore,
    target_kind: str = "fake-llm",
    profile: PipelineProfile | None = None,
    target_config: Path | str | None = None,
) -> dict[str, object]:
    target = create_target(target_kind, target_config)
    capabilities = await target.capabilities()
    target_metadata = await target.metadata()
    selected = select_executable_testcases(testcases, capabilities, policy)
    if profile is not None:
        selected = selected[: profile.testcase_limit]
    fingerprint = build_environment_fingerprint(
        {
            "target_build": target_metadata.kind,
            "model_provider": target_metadata.provider,
            "model_name": target_metadata.name,
            "model_version": target_metadata.version,
            "temperature": 0,
            "seed": 0,
            "system_prompt_hash": "none",
            "tool_schema_hash": "none",
            "rag_corpus_hash": target_metadata.extra.get("rag_corpus_hash", "none"),
            "testcase_version": "basic",
            "policy_hash": policy.policy_hash,
        }
    )
    run = Run(
        target_id=target_metadata.id,
        policy_hash=policy.policy_hash,
        fingerprint=fingerprint["fingerprint"],
    )
    store.initialize()
    store.insert_target(
        Target(
            id=target_metadata.id,
            kind=target_metadata.kind,
            base_url=target_metadata.base_url,
            capabilities=capabilities.to_dict(),
            metadata=asdict(target_metadata),
        )
    )
    store.insert_run(run)

    executor = Executor(
        policy=policy,
        target=target,
        store=store,
        target_id=target_metadata.id,
        options=profile.executor if profile is not None else None,
    )
    judges = JudgeEnsemble(profile.judges) if profile is not None else JudgeEnsemble.default()
    reproducer = Reproducer(
        target=target,
        judges=judges,
        default_attempts=profile.reproduction_attempts if profile is not None else 1,
        default_threshold=profile.reproduction_threshold if profile is not None else None,
    )
    mutation_engine = MutationEngine(strategies=profile.mutation_strategies) if profile is not None else MutationEngine()
    findings: list[Finding] = []
    reports: list[str] = []
    reproduction_summary = {"confirmed": 0, "unstable": 0, "rejected": 0}
    mutation_allowed = profile is None or profile.mutation_enabled
    budget = AttackBudget(
        max_requests=profile.budget_max_requests if profile is not None else None,
        max_tokens=profile.budget_max_tokens if profile is not None else None,
        max_cost_usd=profile.budget_max_cost_usd if profile is not None else None,
        max_runtime_minutes=profile.budget_max_runtime_minutes if profile is not None else None,
        per_suite_requests=profile.budget_per_suite if profile is not None else None,
    )
    consecutive_target_errors = 0
    executed_testcases: list[str] = []

    for case in selected:
        decision = budget.check(category=case.category)
        if not decision.allowed:
            break
        if case.mutation.get("enabled", False) and mutation_allowed:
            for mutation in mutation_engine.mutate(case):
                store.insert_mutation(mutation.to_record())
        try:
            await _process_case(
                run=run,
                case=case,
                executor=executor,
                judges=judges,
                reproducer=reproducer,
                store=store,
                target_metadata=target_metadata,
                findings=findings,
                reports=reports,
                reproduction_summary=reproduction_summary,
                budget=budget,
            )
            executed_testcases.append(case.id)
            consecutive_target_errors = 0
        except TargetError:
            consecutive_target_errors += 1
            if consecutive_target_errors >= _MAX_CONSECUTIVE_TARGET_ERRORS:
                budget.stop_reason = "repeated_target_errors"
                break

    clusters = _cluster_and_report(run, findings, reports)

    return {
        "run_id": run.id,
        "selected_testcases": [case.id for case in selected],
        "executed_testcases": executed_testcases,
        "finding_count": len(findings),
        "reports": reports,
        "fingerprint": run.fingerprint,
        "target": target_metadata.id,
        "coverage": coverage_summary(
            build_coverage_matrix(testcases, capabilities, {case.id for case in selected})
        ),
        "reproductions": reproduction_summary,
        "clusters": clusters,
        "budget": budget.usage,
    }


def _cluster_and_report(run: Run, findings: list[Finding], reports: list[str]) -> list[dict[str, object]]:
    if not findings:
        return []
    clusters = cluster_findings(findings)
    report_path = write_cluster_report(Path("reports/shareable"), run, clusters)
    reports.append(str(report_path))
    return [cluster.to_dict() for cluster in clusters]


def _session_id_for(run: Run, target_id: str, case: Testcase) -> str | None:
    """Design doc section 8.2 Session Strategy. Returns None for the default
    per_testcase isolation (Executor then falls back to session_for_trace,
    i.e. one fresh session per execute() call). shared_suite scopes a
    session to (run, category) so a themed group of testcases in the same
    run can build on each other's state; persistent scopes it to (target,
    category) only, so it's stable across separate runs against the same
    target -- for long-lived memory/persistence testing, used sparingly per
    the doc's own guidance.
    """
    if case.session_strategy == "shared_suite":
        return f"{run.id}:{case.category}"
    if case.session_strategy == "persistent":
        return f"persistent:{target_id}:{case.category}"
    return None


async def _process_case(
    run: Run,
    case: Testcase,
    executor: Executor,
    judges: JudgeEnsemble,
    reproducer: Reproducer,
    store: SQLiteStore,
    target_metadata: TargetMetadata,
    findings: list[Finding],
    reports: list[str],
    reproduction_summary: dict[str, int],
    mutation_id: str | None = None,
    budget: AttackBudget | None = None,
) -> Finding | None:
    store.insert_testcase(
        StoredTestcase(
            id=case.id,
            name=case.name,
            category=case.category,
            content_hash=case.content_hash,
            frameworks=case.frameworks,
        )
    )
    store.insert_prompt(
        PromptRecord(testcase_id=case.id, prompt_hash=case.content_hash, text=case.prompt, mutation_id=mutation_id)
    )
    trace = Trace(run_id=run.id, testcase_id=case.id)
    store.insert_trace(trace)
    request = RequestRecord(
        run_id=run.id,
        trace_id=trace.id,
        testcase_id=case.id,
        prompt_hash=case.content_hash,
        metadata={"target_id": target_metadata.id, "mutation_id": mutation_id},
    )
    store.insert_request(request)
    response = await executor.execute(
        run=run,
        trace=trace,
        testcase=case,
        url=target_metadata.base_url,
        session_id=_session_id_for(run, target_metadata.id, case),
    )
    store.insert_response(
        ResponseRecord(
            request_id=request.id,
            trace_id=trace.id,
            status_code=200,
            token_count=len(response.text.split()),
            metadata=response.metadata,
        )
    )
    judgement = judges.judge(run.id, case, response.text)
    store.insert_judgement(judgement)
    if budget is not None:
        usage = response.metadata.get("usage") if isinstance(response.metadata, dict) else None
        tokens = usage.get("total_tokens") if isinstance(usage, dict) else None
        budget.commit_usage(category=case.category, tokens=int(tokens or len(response.text.split())))
    evidence_bundle = write_evidence_bundle(
        Path("evidence/raw"),
        Path("evidence/sanitized"),
        f"{run.id}_{case.id}.json",
        {
            "prompt": response.prompt,
            "response": response.text,
            "trace_id": trace.id,
            "judgement": judgement.reason,
            "environment_fingerprint": run.fingerprint,
        },
    )
    evidence = store.record_evidence(run.id, "llm_response", evidence_bundle.sanitized_path)
    if not judgement.passed:
        return None

    reproduction = await reproducer.reproduce(case, session_prefix=f"{run.id}:{case.id}")
    finding = Finding(
        run_id=run.id,
        testcase_id=case.id,
        title=case.name,
        category=case.category,
        status=reproduction.status,
        confidence=judgement.score,
        severity=case.severity.get("base", "medium"),
        evidence_ref=evidence.id,
    )
    store.insert_finding(finding)
    store.insert_reproduction(reproduction.to_record(finding.id))
    reproduction_summary[finding.status.value] = reproduction_summary.get(finding.status.value, 0) + 1
    if finding.status in {FindingStatus.CONFIRMED, FindingStatus.UNSTABLE}:
        findings.append(finding)
        metadata = evidence_bundle.to_dict()
        report = write_markdown_report(
            Path("reports/shareable"),
            run,
            case,
            finding,
            judgement,
            evidence_bundle.sanitized_path,
            reproduction=reproduction,
            evidence_metadata=metadata,
        )
        json_report = write_json_report(
            Path("reports/shareable"),
            run,
            case,
            finding,
            judgement,
            metadata,
            reproduction=reproduction,
        )
        store.record_report(run.id, report)
        store.record_report(run.id, json_report)
        reports.extend([str(report), str(json_report)])
    return finding


async def run_adaptive_pipeline(
    policy: PolicyEngine,
    testcases: list[Testcase],
    store: SQLiteStore,
    pyrit_input: Path | str,
    target_kind: str = "fake-llm",
    target_config: Path | str | None = None,
) -> dict[str, object]:
    target = create_target(target_kind, target_config)
    capabilities = await target.capabilities()
    target_metadata = await target.metadata()
    testcase_by_id = {case.id: case for case in testcases}

    fingerprint = build_environment_fingerprint(
        {
            "target_build": target_metadata.kind,
            "model_provider": target_metadata.provider,
            "model_name": target_metadata.name,
            "model_version": target_metadata.version,
            "temperature": 0,
            "seed": 0,
            "system_prompt_hash": "none",
            "tool_schema_hash": "none",
            "rag_corpus_hash": target_metadata.extra.get("rag_corpus_hash", "none"),
            "testcase_version": "adaptive",
            "policy_hash": policy.policy_hash,
        }
    )
    run = Run(
        target_id=target_metadata.id,
        policy_hash=policy.policy_hash,
        fingerprint=fingerprint["fingerprint"],
    )
    store.initialize()
    store.insert_target(
        Target(
            id=target_metadata.id,
            kind=target_metadata.kind,
            base_url=target_metadata.base_url,
            capabilities=capabilities.to_dict(),
            metadata=asdict(target_metadata),
        )
    )
    store.insert_run(run)

    pyrit_results = PyRITAdapter().parse_file(pyrit_input, run_id=run.id, target_id=target_metadata.id)
    planner = AdaptivePlanner()
    executor = Executor(policy=policy, target=target, store=store, target_id=target_metadata.id)
    judges = JudgeEnsemble.default()
    reproducer = Reproducer(target=target, judges=judges)

    findings: list[Finding] = []
    reports: list[str] = []
    reproduction_summary = {"confirmed": 0, "unstable": 0, "rejected": 0}
    plans: list[dict[str, object]] = []
    consecutive_target_errors = 0

    for result in pyrit_results:
        base_case = testcase_by_id.get(result.testcase_id) if result.testcase_id else None
        if base_case is None or not capabilities.supports(base_case.requires):
            continue
        if not policy.validate_testcase(base_case.category).allowed:
            continue
        plan = planner.plan_from_result(result, base_case)
        plans.append(plan.to_dict())
        for mutation in plan.mutations:
            store.insert_mutation(mutation.to_record())
            mutated_case = replace(base_case, id=f"{base_case.id}::{mutation.id}", prompt=mutation.prompt)
            try:
                await _process_case(
                    run=run,
                    case=mutated_case,
                    executor=executor,
                    judges=judges,
                    reproducer=reproducer,
                    store=store,
                    target_metadata=target_metadata,
                    findings=findings,
                    reports=reports,
                    reproduction_summary=reproduction_summary,
                    mutation_id=mutation.id,
                )
                consecutive_target_errors = 0
            except TargetError:
                consecutive_target_errors += 1
                if consecutive_target_errors >= _MAX_CONSECUTIVE_TARGET_ERRORS:
                    break
        if consecutive_target_errors >= _MAX_CONSECUTIVE_TARGET_ERRORS:
            break

    clusters = _cluster_and_report(run, findings, reports)

    return {
        "run_id": run.id,
        "target": target_metadata.id,
        "pyrit_seed_results": len(pyrit_results),
        "plans": plans,
        "finding_count": len(findings),
        "reports": reports,
        "fingerprint": run.fingerprint,
        "reproductions": reproduction_summary,
        "clusters": clusters,
    }


_EXTERNAL_SCAN_ADAPTERS = {
    "nuclei": NucleiAdapter,
    "dalfox": DalfoxAdapter,
    "trufflehog": TruffleHogAdapter,
}


def _normalize_external_scan(inputs: dict[str, Path | str | None]) -> dict[str, object]:
    summary: dict[str, object] = {}
    for tool, adapter_cls in _EXTERNAL_SCAN_ADAPTERS.items():
        path = inputs.get(tool)
        if path is None:
            continue
        results = adapter_cls().parse_file(path, run_id=new_id("run"), target_id="external_scan")
        summary[tool] = {"count": len(results), "findings": [result.to_dict() for result in results]}
    return summary


async def run_full_pipeline(
    policy: PolicyEngine,
    testcases: list[Testcase],
    store: SQLiteStore,
    profile: PipelineProfile,
    recon_inputs: dict[str, Path | str | None] | None = None,
    pyrit_input: Path | str | None = None,
    external_inputs: dict[str, Path | str | None] | None = None,
) -> dict[str, object]:
    """Ties scope/policy -> recon -> classify -> scan -> judge -> reproduce ->
    dedup -> report into a single run, gated by the active profile's stages.
    """
    store.initialize()
    result: dict[str, object] = {"profile": profile.name, "stages": profile.stages}

    if "recon" in profile.stages and recon_inputs:
        result["recon"] = build_asset_map(
            policy,
            store,
            run_id=new_id("run"),
            target_id="recon",
            subfinder_input=recon_inputs.get("subfinder"),
            httpx_input=recon_inputs.get("httpx"),
            katana_input=recon_inputs.get("katana"),
            ffuf_input=recon_inputs.get("ffuf"),
        )

    scan_run_ids: list[str] = []
    scan_results: dict[str, object] = {}
    if "scan" in profile.stages:
        for target_kind in profile.targets:
            pipeline_result = await run_sample_pipeline(policy, testcases, store, target_kind=target_kind, profile=profile)
            scan_results[target_kind] = pipeline_result
            scan_run_ids.append(str(pipeline_result["run_id"]))
    result["scan"] = scan_results

    if "adaptive" in profile.stages and pyrit_input:
        adaptive_target = profile.targets[0] if profile.targets else "fake-llm"
        adaptive_result = await run_adaptive_pipeline(policy, testcases, store, pyrit_input, target_kind=adaptive_target)
        result["adaptive"] = adaptive_result
        scan_run_ids.append(str(adaptive_result["run_id"]))

    if "external_scan" in profile.stages and external_inputs:
        result["external_scan"] = _normalize_external_scan(external_inputs)

    all_reports: list[str] = []
    for pipeline_result in scan_results.values():
        all_reports.extend(pipeline_result["reports"])
    if "adaptive" in result:
        all_reports.extend(result["adaptive"]["reports"])

    combined_findings = (
        [
            finding
            for finding in store.list_findings(scan_run_ids)
            if finding.status in {FindingStatus.CONFIRMED, FindingStatus.UNSTABLE}
        ]
        if scan_run_ids
        else []
    )
    if combined_findings:
        clusters = cluster_findings(combined_findings)
        combined_run = Run(target_id="full", policy_hash=policy.policy_hash, fingerprint="combined")
        report_path = write_cluster_report(Path("reports/shareable"), combined_run, clusters)
        all_reports.append(str(report_path))
        result["combined_clusters"] = [cluster.to_dict() for cluster in clusters]
    else:
        result["combined_clusters"] = []

    result["reports"] = all_reports
    result["finding_count"] = len(combined_findings)
    return result


async def run_live_scan_pipeline(
    policy: PolicyEngine,
    testcases: list[Testcase],
    store: SQLiteStore,
    profile: PipelineProfile,
    url: str,
    max_pages: int = 5,
    auto_profile: bool = False,
    pack_target: str | None = None,
    pack_target_config: Path | str | None = None,
    pack_budget_requests: int | None = None,
    external_scan_inputs: dict[str, Path | str | None] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, object]:
    """P3.1-1 (roadmap v3.1.0 Operational Pipeline): `scan <url>`'s LIVE
    MODE entry point. Wires U4-U7 (discover -> classify -> auto-profile ->
    pack select -> pack run) into one call by reusing each stage's
    existing internal API, instead of requiring separate
    `discover --classify --auto-profile --select-packs --run-packs`
    invocations. Purely additive: run_full_pipeline (the fixture-driven
    --profile path used by the golden regression baseline) is untouched.
    """
    # Local import: packs.runner imports run_sample_pipeline from this
    # module, so importing it at module scope here would be circular.
    from packs.runner import run_selected_packs

    store.initialize()
    discovery = await discover_target(url, policy, max_pages=max_pages, transport=transport)
    candidates = classify_items(discovery.items)

    auto_profile_results = (
        await auto_profile_candidates(candidates, policy, store, transport=transport) if auto_profile else []
    )

    budget = AttackBudget(max_requests=pack_budget_requests) if pack_budget_requests else None
    target_kinds = {candidate.kind for candidate in candidates}
    selections = select_packs(target_kinds, policy, budget=budget)

    pack_runs = await run_selected_packs(
        selections,
        testcases,
        policy,
        store,
        target_kind=pack_target,
        target_config=pack_target_config,
        profile=profile,
        external_scan_inputs={k: v for k, v in (external_scan_inputs or {}).items() if v is not None},
        live_target_url=url,
    )

    scan_run_ids = [
        str(pack_run.summary["run_id"])
        for pack_run in pack_runs
        if pack_run.tool_id == "testcase_suite" and pack_run.summary is not None
    ]
    findings = (
        [
            finding
            for finding in store.list_findings(scan_run_ids)
            if finding.status in {FindingStatus.CONFIRMED, FindingStatus.UNSTABLE}
        ]
        if scan_run_ids
        else []
    )
    reports: list[str] = []
    for pack_run in pack_runs:
        if pack_run.tool_id == "testcase_suite" and pack_run.summary is not None:
            reports.extend(pack_run.summary.get("reports", []))

    combined_run = Run(target_id="live_scan", policy_hash=policy.policy_hash, fingerprint=f"live_scan:{url}")
    clusters = _cluster_and_report(combined_run, findings, reports)

    return {
        "mode": "live",
        "url": url,
        "profile": profile.name,
        "discovery": discovery.to_dict(),
        "classification": [candidate.to_dict() for candidate in candidates],
        "auto_profile": [result.to_dict() for result in auto_profile_results],
        "pack_selection": [selection.to_dict() for selection in selections],
        "pack_runs": [pack_run.to_dict() for pack_run in pack_runs],
        "finding_count": len(findings),
        "clusters": clusters,
        "reports": reports,
    }


async def run_profile_target(
    policy: PolicyEngine,
    store: SQLiteStore,
    target_kind: str = "fake-llm",
    target_config: Path | str | None = None,
    probe: bool = True,
) -> dict[str, object]:
    store.initialize()
    target = create_target(target_kind, target_config)
    target_metadata = await target.metadata()
    capabilities = await target.capabilities()
    run = Run(target_id=target_metadata.id, policy_hash=policy.policy_hash, fingerprint="profile")
    store.insert_target(
        Target(
            id=target_metadata.id,
            kind=target_metadata.kind,
            base_url=target_metadata.base_url,
            capabilities=capabilities.to_dict(),
            metadata=asdict(target_metadata),
        )
    )
    store.insert_run(run)
    executor = Executor(policy=policy, target=target, store=store, target_id=target_metadata.id)
    profile = await profile_target(executor, target, run, store, probe=probe)
    return profile.to_dict()


async def _reproduce_scenario_finding(
    policy: PolicyEngine,
    store: SQLiteStore,
    finding: Finding,
    target_kind: str,
    target_config: Path | str | None,
    minimize: bool,
) -> dict[str, object]:
    """P3.1-2 (roadmap v3.1.0 Operational Pipeline): `reproduce`'s branch
    for a scenario-origin Finding. The Finding's reproduction_spec is a
    self-contained snapshot of the scenario (see scenario/finding.py), so
    this never needs the original --scenarios YAML file back.
    """
    spec = finding.reproduction_spec
    scenario = Scenario(
        id=spec["scenario_id"],
        name=spec.get("scenario_name", spec["scenario_id"]),
        steps=[ScenarioStep(**step) for step in spec["steps"]],
        description=spec.get("scenario_description", ""),
    )
    step_id = spec["step_id"]

    target = create_target(target_kind, target_config)
    target_metadata = await target.metadata()
    judges = JudgeEnsemble.default()
    executor = Executor(policy=policy, target=target, store=store, target_id=target_metadata.id)

    store.initialize()
    run = Run(target_id=target_metadata.id, policy_hash=policy.policy_hash, fingerprint=f"reproduce_scenario:{finding.id}")
    control_run = Run(
        target_id=target_metadata.id, policy_hash=policy.policy_hash, fingerprint=f"reproduce_scenario_control:{finding.id}"
    )
    store.insert_run(run)
    store.insert_run(control_run)

    outcome = await reproduce_scenario_finding(scenario, step_id, executor, judges, store, run, control_run, target_metadata.base_url)

    result: dict[str, object] = {
        "finding_id": finding.id,
        "testcase_id": finding.testcase_id,
        "original_status": finding.status.value,
        "reproduction": {
            "type": "scenario",
            "scenario_id": outcome.scenario_id,
            "step_id": outcome.step_id,
            "attack_passed": outcome.attack_passed,
            "control_passed": outcome.control_passed,
            "status": outcome.status.value,
        },
        "scenario_result": outcome.result.to_dict(),
        "control_result": outcome.control_result.to_dict(),
    }
    if minimize:
        # Segment-removal minimization (reproduction/minimal_poc.py) is
        # defined for a single prompt, not a multi-step/multi-session
        # scenario -- reported explicitly rather than silently ignored.
        result["minimal_poc"] = None
        result["minimal_poc_note"] = "minimization is not yet supported for scenario findings"
    return result


async def run_reproduce_finding(
    policy: PolicyEngine,
    testcases: list[Testcase],
    store: SQLiteStore,
    finding_id: str,
    target_kind: str = "fake-llm",
    target_config: Path | str | None = None,
    minimize: bool = False,
) -> dict[str, object]:
    """Re-runs reproduction for a previously stored Finding against a live
    target -- e.g. "did the program fix this since I first found it?" --
    and, if it still reproduces, optionally minimizes the prompt to a
    submittable PoC (design doc section 10).

    Unlike a normal scan, this intentionally does not re-validate the
    testcase suite's structure beyond needing the seed testcase for its
    judges/severity: the actual prompt replayed is the exact one stored in
    the run that first produced this finding (prompts.text), not whatever
    the current suite file happens to contain.
    """
    finding = store.get_finding(finding_id)
    if finding is None:
        raise ValueError(f"finding not found: {finding_id}")

    if finding.reproduction_spec.get("type") == "scenario":
        return await _reproduce_scenario_finding(policy, store, finding, target_kind, target_config, minimize)

    base_id = base_testcase_id(finding.testcase_id)
    base_case = next((case for case in testcases if case.id == base_id), None)
    if base_case is None:
        raise ValueError(f"seed testcase '{base_id}' not found in the provided --testcases suite")

    prompt_text = store.get_latest_prompt_text(finding.testcase_id) or base_case.prompt
    case = replace(base_case, id=finding.testcase_id, prompt=prompt_text)

    target = create_target(target_kind, target_config)
    judges = JudgeEnsemble(case.judges)
    reproducer = Reproducer(target=target, judges=judges)

    session_prefix = f"reproduce:{finding_id}"
    outcome = await reproducer.reproduce(case, session_prefix=session_prefix)

    result: dict[str, object] = {
        "finding_id": finding_id,
        "testcase_id": finding.testcase_id,
        "original_status": finding.status.value,
        "reproduction": {
            "attempts": outcome.attempts,
            "successes": outcome.successes,
            "threshold": outcome.threshold,
            "success_rate": outcome.success_rate,
            "control_passed": outcome.control_passed,
            "status": outcome.status.value,
        },
    }

    if minimize and outcome.status in {FindingStatus.CONFIRMED, FindingStatus.UNSTABLE}:
        poc = await minimize_poc(case, target, judges, session_prefix=session_prefix)
        result["minimal_poc"] = poc.to_dict()
        evidence_bundle = write_evidence_bundle(
            Path("evidence/raw"),
            Path("evidence/sanitized"),
            f"{finding_id}_minimal_poc.json",
            {
                "finding_id": finding_id,
                "original_prompt": poc.original_prompt,
                "minimized_prompt": poc.minimized_prompt,
                "removed_segments": poc.removed_segments,
            },
        )
        evidence = store.record_evidence(finding.run_id, "minimal_poc", evidence_bundle.sanitized_path)
        result["minimal_poc_evidence_id"] = evidence.id

    return result
