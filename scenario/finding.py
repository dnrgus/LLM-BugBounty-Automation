from __future__ import annotations

from pathlib import Path

from core.models import Finding, FindingStatus
from reporting.evidence import write_evidence_bundle
from scenario.models import Scenario, ScenarioResult
from storage.sqlite import SQLiteStore


def _step_spec(step) -> dict[str, object]:  # noqa: ANN001 -- ScenarioStep, kept structurally typed for JSON round-trip
    return {
        "id": step.id,
        "prompt": step.prompt,
        "session_ref": step.session_ref,
        "category": step.category,
        "judges": step.judges,
    }


def promote_scenario_result(scenario: Scenario, result: ScenarioResult, store: SQLiteStore) -> list[Finding]:
    """P3.1-2 (roadmap v3.1.0 Operational Pipeline): promotes each flagged
    step of a Scenario run into a first-class Finding, exactly like
    core/orchestrator.py's _process_case does for a single testcase --
    with its own Evidence bundle (holding every step's trace, not just
    the flagged one, so replaying later has full context) and a
    reproduction_spec self-contained enough for `reproduce <finding-id>`
    to replay it without the original --scenarios YAML file.
    """
    steps_by_id = {step.id: step for step in scenario.steps}
    steps_spec = [_step_spec(step) for step in scenario.steps]
    findings: list[Finding] = []

    for step_result in result.steps:
        if not step_result.judgement_passed:
            continue
        step = steps_by_id[step_result.step_id]
        evidence_bundle = write_evidence_bundle(
            Path("evidence/raw"),
            Path("evidence/sanitized"),
            f"{result.run_id}_{scenario.id}_{step_result.step_id}.json",
            {
                "scenario_id": scenario.id,
                "flagged_step_id": step_result.step_id,
                "steps": [s.to_dict() for s in result.steps],
                "judgement": step_result.judgement_reason,
            },
        )
        evidence = store.record_evidence(result.run_id, "scenario_response", evidence_bundle.sanitized_path)
        finding = Finding(
            run_id=result.run_id,
            testcase_id=f"{scenario.id}:{step_result.step_id}",
            title=f"{scenario.name} / {step_result.step_id}",
            category=step.category,
            status=FindingStatus.CANDIDATE,
            confidence=step_result.judgement_score,
            severity="medium",
            evidence_ref=evidence.id,
            reproduction_spec={
                "type": "scenario",
                "scenario_id": scenario.id,
                "scenario_name": scenario.name,
                "scenario_description": scenario.description,
                "step_id": step_result.step_id,
                "steps": steps_spec,
            },
        )
        store.insert_finding(finding)
        findings.append(finding)

    return findings
