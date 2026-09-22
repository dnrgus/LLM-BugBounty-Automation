"""P4.1-E dedup extension (roadmap v4.1.0): validation-task-originated
Findings dedup on candidate fingerprint + target entity + validator_type,
not on testcase_id (a fresh random ValidationTask id every re-run).
"""

from core.models import Finding, FindingStatus
from findings.dedup import cluster_findings


def _validation_finding(
    validator_type: str, static_candidate_id: str, target_entity: str, task_id: str, status=FindingStatus.CONFIRMED
) -> Finding:
    return Finding(
        run_id="run-1",
        testcase_id=task_id,
        title=f"{validator_type} validation: {static_candidate_id}",
        category=validator_type,
        status=status,
        confidence=0.9,
        severity="high",
        evidence_ref="ev-1",
        reproduction_spec={"type": "validation", "validator_type": validator_type, "task_id": task_id, "target_entity": target_entity},
        origin=["static", "dynamic"],
        static_candidate_id=static_candidate_id,
        validation_task_ids=[task_id],
        validation_status=status.value,
    )


def test_repeated_validation_of_same_candidate_and_target_dedups_together() -> None:
    first = _validation_finding("auth", "AS-1", "https://ai.example.com/api/resource/1", "vtask-1")
    second = _validation_finding("auth", "AS-1", "https://ai.example.com/api/resource/1", "vtask-2")

    clusters = cluster_findings([first, second])

    assert len(clusters) == 1
    assert set(clusters[0].finding_ids) == {first.id, second.id}


def test_same_candidate_different_target_entity_does_not_dedup() -> None:
    first = _validation_finding("auth", "AS-1", "https://ai.example.com/api/resource/1", "vtask-1")
    second = _validation_finding("auth", "AS-1", "https://ai.example.com/api/resource/2", "vtask-2")

    clusters = cluster_findings([first, second])

    assert len(clusters) == 2


def test_same_target_different_validator_type_does_not_dedup() -> None:
    first = _validation_finding("auth", "AS-1", "https://ai.example.com/api/resource/1", "vtask-1")
    second = _validation_finding("endpoint", "AS-1", "https://ai.example.com/api/resource/1", "vtask-2")

    clusters = cluster_findings([first, second])

    assert len(clusters) == 2


def test_validation_finding_does_not_dedup_with_a_plain_testcase_finding() -> None:
    validation_finding = _validation_finding("endpoint", "AS-1", "https://ai.example.com/api/resource/1", "vtask-1")
    plain_finding = Finding(
        run_id="run-1", testcase_id="LLM-SP-001", title="System prompt leak",
        category="endpoint", status=FindingStatus.CONFIRMED, confidence=0.9, severity="high", evidence_ref="ev-2",
    )

    clusters = cluster_findings([validation_finding, plain_finding])

    assert len(clusters) == 2
