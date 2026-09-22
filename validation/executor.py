from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

from attack_surface.models import AttackSurfaceItem
from core.orchestrator import run_sample_pipeline
from core.profile import PipelineProfile
from correlation.resolver import EntityMatch
from findings.correlation import CorrelatedFinding
from packs.registry import DEFAULT_PACKS
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from testcase.schema import Testcase
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
