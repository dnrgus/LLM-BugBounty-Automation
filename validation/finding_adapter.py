from __future__ import annotations

from core.models import Finding, FindingStatus
from validation.contract import ValidationResult, ValidationStatus, ValidationTask

# P4.1-E (roadmap v4.1.0 Dynamic Validation Expansion): only a
# *terminal* ValidationStatus becomes a Finding -- PLANNED/EXECUTABLE/
# RUNNING haven't reached a verdict yet, and BLOCKED means no check was
# even attempted, so none of those are worth a Finding row.
# REVIEW_ONLY maps to FindingStatus.CANDIDATE (still needs a human
# decision), mirroring legacy_adapter's own reverse mapping
# (FindingStatus.CANDIDATE -> ValidationStatus.REVIEW_ONLY).
_VALIDATION_TO_FINDING_STATUS: dict[ValidationStatus, FindingStatus] = {
    ValidationStatus.CONFIRMED: FindingStatus.CONFIRMED,
    ValidationStatus.REJECTED: FindingStatus.REJECTED,
    ValidationStatus.UNSTABLE: FindingStatus.UNSTABLE,
    ValidationStatus.REVIEW_ONLY: FindingStatus.CANDIDATE,
}

# What a CONFIRMED result from each validator type actually means --
# used for severity, and to keep report language honest about scope.
_SEVERITY_BY_VALIDATOR_TYPE = {
    "endpoint": "info",  # confirms reachability, not a vulnerability
    "auth": "high",  # a genuine broken-access-control signal
    "dataflow": "medium",  # a reflected correlation token, not a proven sink hit
}

LIMITATIONS_BY_VALIDATOR_TYPE = {
    "endpoint": "Confirms only that the candidate endpoint is live and reachable -- reachability is not itself a vulnerability.",
    "auth": "Confirms only that two explicitly supplied fixture/env/browser-session contexts observed the same "
    "response shape -- never derived from a guessed or brute-forced credential.",
    "dataflow": "Confirms only that a harmless correlation token was reflected somewhere observable -- not that it "
    "reached the specific traced sink, and the sink's real payload/behavior was never triggered.",
}


def finding_from_validation_result(
    run_id: str,
    task: ValidationTask,
    result: ValidationResult,
    evidence_ref: str,
    target_entity: str,
) -> Finding | None:
    """Builds a Finding from an endpoint/auth/dataflow ValidationResult
    -- the same role validation/legacy_adapter.py's
    validation_results_from_dynamic_outcome plays for the llm/rag/agent
    path, just in the opposite direction (result -> Finding rather than
    outcome -> result), since those validators don't route through the
    existing testcase_suite pack pipeline that already creates Findings
    itself.
    """
    finding_status = _VALIDATION_TO_FINDING_STATUS.get(result.status)
    if finding_status is None:
        return None
    return Finding(
        run_id=run_id,
        testcase_id=task.id,
        title=f"{task.validator_type} validation: {task.candidate_id}",
        category=task.validator_type,
        status=finding_status,
        confidence=result.confidence,
        severity=_SEVERITY_BY_VALIDATOR_TYPE.get(task.validator_type, "info"),
        evidence_ref=evidence_ref,
        reproduction_spec={
            "type": "validation",
            "validator_type": task.validator_type,
            "task_id": task.id,
            "target_entity": target_entity,
        },
        origin=["static", "dynamic"],
        static_candidate_id=task.candidate_id,
        validation_task_ids=[task.id],
        validation_status=result.status.value,
    )
