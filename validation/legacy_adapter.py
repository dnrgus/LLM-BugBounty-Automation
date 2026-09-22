from __future__ import annotations

from core.models import FindingStatus
from validation.contract import ValidationResult, ValidationStatus, ValidationTask
from validation.executor import DynamicValidationOutcome
from validation.planner import ValidationPlan

_CLASSIFICATION_TO_STATUS = {
    "executable": ValidationStatus.EXECUTABLE,
    "review_only": ValidationStatus.REVIEW_ONLY,
    "unsupported": ValidationStatus.BLOCKED,
}

_FINDING_STATUS_TO_VALIDATION_STATUS = {
    FindingStatus.CONFIRMED: ValidationStatus.CONFIRMED,
    FindingStatus.REJECTED: ValidationStatus.REJECTED,
    FindingStatus.UNSTABLE: ValidationStatus.UNSTABLE,
    FindingStatus.CANDIDATE: ValidationStatus.REVIEW_ONLY,
}

_ASSET_TYPE_TO_VALIDATOR_TYPE = {
    "llm": "llm_core",
    "rag": "rag_injection",
    "agent": "agent_tool_abuse",
    "endpoint": "endpoint",
    "auth": "auth",
    "dataflow": "dataflow",
}

# Preference order when one ValidationTask's execution produced several
# ValidationResults with different statuses (a multi-testcase pack run
# can confirm one finding while rejecting another) -- the task's own
# terminal status is the most significant signal observed, not
# arbitrarily "the last one".
_STATUS_PRIORITY = (
    ValidationStatus.CONFIRMED,
    ValidationStatus.UNSTABLE,
    ValidationStatus.REJECTED,
    ValidationStatus.REVIEW_ONLY,
)


def validation_task_from_plan(plan: ValidationPlan) -> ValidationTask:
    """P4.1-A (roadmap v4.1.0 Dynamic Validation Expansion): wraps an
    existing validation/planner.py ValidationPlan (v3.3.0) in the new
    unified ValidationTask contract, so legacy llm/rag/agent planning
    keeps working completely unchanged behind the new lifecycle model
    -- this function never touches validation/planner.py itself.
    """
    task = ValidationTask(
        candidate_id=plan.candidate_id,
        validator_type=_ASSET_TYPE_TO_VALIDATOR_TYPE.get(plan.asset_type, plan.asset_type),
        prerequisites=list(plan.required_context),
        risk_level="high" if plan.requires_approval else "low",
        budget_hint={},
    )
    target_status = _CLASSIFICATION_TO_STATUS[plan.classification]
    if target_status is not ValidationStatus.PLANNED:
        task.transition(target_status)
    return task


def validation_results_from_dynamic_outcome(
    task: ValidationTask, outcome: DynamicValidationOutcome
) -> list[ValidationResult]:
    """Wraps validation/executor.py's DynamicValidationOutcome (v3.3.0)
    into one or more ValidationResults -- one legacy outcome can carry
    more than one correlated Finding (a pack run covers several
    testcase categories at once), so this returns one ValidationResult
    per correlated finding and advances `task` through RUNNING to its
    single most-significant terminal status.
    """
    if outcome.status != "ran" or not outcome.correlated_findings:
        return []

    if task.status is ValidationStatus.EXECUTABLE:
        task.transition(ValidationStatus.RUNNING)

    results = [
        ValidationResult(
            task_id=task.id,
            status=_FINDING_STATUS_TO_VALIDATION_STATUS[correlated.finding.status],
            confidence=correlated.finding.confidence,
            evidence_refs=[correlated.finding.evidence_ref],
            observations=[correlated.to_dict()],
        )
        for correlated in outcome.correlated_findings
    ]

    observed_statuses = {result.status for result in results}
    final_status = next((status for status in _STATUS_PRIORITY if status in observed_statuses), ValidationStatus.REVIEW_ONLY)
    if task.status is ValidationStatus.RUNNING:
        task.transition(final_status)
    return results
