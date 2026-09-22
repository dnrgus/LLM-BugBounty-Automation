from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

import httpx

from attack_surface.models import AttackSurfaceItem
from core.orchestrator import run_sample_pipeline
from core.profile import PipelineProfile
from correlation.resolver import EntityMatch
from findings.correlation import CorrelatedFinding
from packs.registry import DEFAULT_PACKS
from reporting.evidence import write_evidence_bundle
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from testcase.schema import Testcase
from validation.auth_validator import AuthContext, compare_auth_contexts
from validation.contract import ValidationResult, ValidationStatus, ValidationTask
from validation.dataflow_validator import DataflowInjectionPoint, validate_dataflow_correlation
from validation.endpoint_validator import EndpointValidationEvidence, validate_endpoint
from validation.finding_adapter import finding_from_validation_result
from validation.planner import ValidationPlan

_PACKS_BY_ID = {pack.id: pack for pack in DEFAULT_PACKS}
_PACK_ID_BY_ASSET_TYPE = {"llm": "llm_core", "rag": "rag_injection", "agent": "agent_tool_abuse"}


@dataclass(frozen=True)
class DynamicValidationOutcome:
    item: AttackSurfaceItem
    plan: ValidationPlan
    status: str  # "ran" | "not_run"
    detail: str
    correlated_findings: list[CorrelatedFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "candidate_id": self.item.id,
            "asset_type": self.item.asset_type,
            "classification": self.plan.classification,
            "status": self.status,
            "detail": self.detail,
            "correlated_findings": [correlated.to_dict() for correlated in self.correlated_findings],
        }


async def run_dynamic_validation(
    item: AttackSurfaceItem,
    plan: ValidationPlan,
    match: EntityMatch,
    policy: PolicyEngine,
    testcases: list[Testcase],
    store: SQLiteStore,
    target_kind: str,
    target_config: Path | str | None = None,
    profile: PipelineProfile | None = None,
) -> DynamicValidationOutcome:
    """P3.3-3 (roadmap v3.3.0 Static -> Dynamic Validation): actually
    runs an "executable" ValidationPlan (P3.3-2) for an llm/rag/agent
    capability hint, against the target its EntityMatch (P3.3-1)
    correlated it with.

    This reuses the existing testcase_suite pack pipeline
    (Executor -> JudgeEnsemble -> Reproducer, via run_sample_pipeline)
    for the actual control-vs-attack comparison and confirmed/unstable/
    rejected classification -- that pipeline already does this; this
    function's own job is only to connect *this specific static
    candidate* to that run and tag its resulting Finding(s) with
    dynamic-validation provenance (reproduction_spec["origin"] =
    ["static", "dynamic"], plus the static candidate's id), so a report
    can tell a plain testcase-driven finding apart from one a source
    analysis specifically flagged first.

    Every other classification (review_only, unsupported) and every
    other asset_type (endpoint, dataflow, auth, secret, function,
    parameter) is reported as "not_run" -- this project has no generic
    live executor for those yet; llm/rag/agent's testcase_suite pack is
    the only one that exists.
    """
    if plan.classification != "executable" or item.asset_type not in _PACK_ID_BY_ASSET_TYPE:
        return DynamicValidationOutcome(
            item, plan, "not_run",
            f"no dynamic executor available for classification={plan.classification!r} asset_type={item.asset_type!r}",
        )

    pack_id = _PACK_ID_BY_ASSET_TYPE[item.asset_type]
    pack = _PACKS_BY_ID.get(pack_id)
    if pack is None:
        return DynamicValidationOutcome(item, plan, "not_run", f"no registered pack for {pack_id!r}")

    filtered = [case for case in testcases if case.category in pack.testing_categories]
    if not filtered:
        return DynamicValidationOutcome(
            item, plan, "not_run",
            f"no testcases in the supplied suite match categories {sorted(pack.testing_categories)}",
        )

    pipeline_result = await run_sample_pipeline(
        policy, filtered, store, target_kind=target_kind, target_config=target_config, profile=profile
    )
    run_id = str(pipeline_result["run_id"])

    correlated: list[CorrelatedFinding] = []
    for finding in store.list_findings([run_id]):
        spec = dict(finding.reproduction_spec)
        spec["origin"] = ["static", "dynamic"]
        spec["static_candidate_id"] = item.id
        spec["entity_match_basis"] = match.basis
        store.update_finding_reproduction_spec(finding.id, spec)
        correlated.append(
            CorrelatedFinding(
                finding=replace(finding, reproduction_spec=spec), static_candidate=item, match=match, plan=plan
            )
        )

    return DynamicValidationOutcome(
        item, plan, "ran",
        f"ran {pack_id} pack ({len(filtered)} testcase(s) across {sorted(pack.testing_categories)}); "
        f"{len(correlated)} finding(s) produced",
        correlated,
    )


def _endpoint_result(task: ValidationTask, evidence: EndpointValidationEvidence, confidence: float) -> ValidationResult:
    if evidence.blocked:
        status = ValidationStatus.BLOCKED
    elif any(observation.status_code is not None for observation in evidence.observations):
        # A real HTTP response (of any status code) confirms the
        # candidate correlates to a live, reachable endpoint -- not a
        # vulnerability verdict, matching EndpointValidationEvidence's
        # own docstring.
        status = ValidationStatus.CONFIRMED
    elif evidence.observations:
        status = ValidationStatus.REJECTED
    else:
        status = ValidationStatus.UNSTABLE
    return ValidationResult(
        task_id=task.id, status=status, confidence=confidence,
        observations=[observation.to_dict() for observation in evidence.observations],
    )


async def run_endpoint_validation(
    item: AttackSurfaceItem,
    plan: ValidationPlan,
    match: EntityMatch,
    policy: PolicyEngine,
    store: SQLiteStore,
    run_id: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> DynamicValidationOutcome:
    """P4.1-E (roadmap v4.1.0 Dynamic Validation Expansion): dispatches
    an "executable" endpoint candidate (item+match already resolved by
    validation/planner.py + correlation/resolver.py) to
    endpoint_validator.py, then wraps the result through the 4.1-A
    ValidationTask/ValidationResult contract into a Finding via
    finding_from_validation_result.
    """
    if plan.classification != "executable" or item.asset_type != "endpoint":
        return DynamicValidationOutcome(
            item, plan, "not_run",
            f"no endpoint executor for classification={plan.classification!r} asset_type={item.asset_type!r}",
        )

    url = match.live_item.location
    method = str(item.metadata.get("method", "GET"))
    evidence = await validate_endpoint(url, method, policy, transport=transport)

    task = ValidationTask(candidate_id=item.id, validator_type="endpoint", status=ValidationStatus.RUNNING)
    result = _endpoint_result(task, evidence, match.confidence)

    evidence_bundle = write_evidence_bundle(
        Path("evidence/raw"), Path("evidence/sanitized"), f"{run_id}_{task.id}_endpoint.json", evidence.to_dict()
    )
    stored_evidence = store.record_evidence(
        run_id, "endpoint_validation", evidence_bundle.sanitized_path, raw_path=evidence_bundle.raw_path
    )

    finding = finding_from_validation_result(run_id, task, result, stored_evidence.id, url)
    if finding is not None:
        store.insert_finding(finding)
    correlated = [CorrelatedFinding(finding=finding, static_candidate=item, match=match, plan=plan)] if finding else []

    return DynamicValidationOutcome(item, plan, "ran", f"endpoint validation -> {result.status.value}", correlated)


async def run_auth_validation(
    item: AttackSurfaceItem,
    match: EntityMatch,
    policy: PolicyEngine,
    control: AuthContext,
    probe: AuthContext,
    store: SQLiteStore,
    run_id: str,
    resource_key: str | None = None,
    selected_fields: list[str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> DynamicValidationOutcome:
    """P4.1-E: runs the auth-context comparison validator for an "auth"
    candidate. Unlike endpoint validation, this is never auto-triggered
    by classification=="executable" -- validation/planner.py
    deliberately keeps every auth candidate at "review_only" (a real
    fixture/env/browser-session AuthContext pair must be explicitly
    supplied by the caller; this project never guesses or brute-forces
    one), so this function is only reached once a caller already has
    that context in hand.
    """
    url = match.live_item.location
    method = str(item.metadata.get("method", "GET"))
    comparison = await compare_auth_contexts(
        url, method, control, probe, policy, resource_key=resource_key, selected_fields=selected_fields, transport=transport
    )

    task = ValidationTask(candidate_id=item.id, validator_type="auth", status=ValidationStatus.RUNNING)
    result = ValidationResult(
        task_id=task.id, status=comparison.status, confidence=match.confidence,
        observations=[observation.to_dict() for observation in comparison.observations],
    )

    evidence_bundle = write_evidence_bundle(
        Path("evidence/raw"), Path("evidence/sanitized"), f"{run_id}_{task.id}_auth.json", comparison.to_dict()
    )
    stored_evidence = store.record_evidence(
        run_id, "auth_validation", evidence_bundle.sanitized_path, raw_path=evidence_bundle.raw_path
    )

    plan = ValidationPlan(
        candidate_id=item.id, asset_type=item.asset_type, classification="review_only",
        reason="auth-context comparison executed with an explicitly supplied context pair",
    )
    finding = finding_from_validation_result(run_id, task, result, stored_evidence.id, comparison.resource_key)
    if finding is not None:
        store.insert_finding(finding)
    correlated = [CorrelatedFinding(finding=finding, static_candidate=item, match=match, plan=plan)] if finding else []

    return DynamicValidationOutcome(item, plan, "ran", f"auth comparison -> {result.status.value}", correlated)


async def run_dataflow_validation(
    item: AttackSurfaceItem,
    policy: PolicyEngine,
    injection: DataflowInjectionPoint,
    target_url: str,
    store: SQLiteStore,
    run_id: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> DynamicValidationOutcome:
    """P4.1-E: runs the dataflow runtime-correlation validator for a
    "dataflow" candidate. Like auth, never auto-triggered by
    classification -- validation/planner.py keeps every dataflow
    candidate at "review_only", and a concrete injection point resolved
    to a live URL must be supplied by the caller (destructive sink
    types are refused inside dataflow_validator.py itself regardless of
    what the caller supplies).
    """
    sink_type = str(item.metadata.get("sink_type", ""))
    evidence = await validate_dataflow_correlation(target_url, sink_type, injection, item.location, policy, transport=transport)

    task = ValidationTask(candidate_id=item.id, validator_type="dataflow", status=ValidationStatus.RUNNING)
    result = ValidationResult(
        task_id=task.id, status=evidence.status, confidence=item.confidence, observations=[evidence.to_dict()]
    )

    evidence_bundle = write_evidence_bundle(
        Path("evidence/raw"), Path("evidence/sanitized"), f"{run_id}_{task.id}_dataflow.json", evidence.to_dict()
    )
    stored_evidence = store.record_evidence(
        run_id, "dataflow_validation", evidence_bundle.sanitized_path, raw_path=evidence_bundle.raw_path
    )

    plan = ValidationPlan(
        candidate_id=item.id, asset_type=item.asset_type, classification="review_only",
        reason="dataflow runtime correlation executed with an explicitly supplied injection point",
    )
    # No live-endpoint EntityMatch applies here (dataflow candidates are
    # probed directly against a caller-supplied URL, not resolved via
    # correlation/resolver.py) -- the candidate is its own provenance.
    match = EntityMatch(source_item=item, live_item=item, confidence=item.confidence, basis=["dataflow_runtime_correlation"])
    finding = finding_from_validation_result(run_id, task, result, stored_evidence.id, target_url)
    if finding is not None:
        store.insert_finding(finding)
    correlated = [CorrelatedFinding(finding=finding, static_candidate=item, match=match, plan=plan)] if finding else []

    return DynamicValidationOutcome(item, plan, "ran", f"dataflow correlation -> {result.status.value}", correlated)
