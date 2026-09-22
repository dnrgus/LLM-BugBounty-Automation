"""P3.1-2 Scenario -> Finding Lifecycle (roadmap v3.1.0 Operational Pipeline).

Covers: promoting flagged scenario steps into first-class, individually
reproducible Findings (scenario/finding.py), the scenario-aware
control-vs-attack reproducer (scenario/reproducer.py), and
`reproduce <finding-id>` dispatching to it end-to-end
(core/orchestrator.py's run_reproduce_finding).
"""

import asyncio
from pathlib import Path

from core.models import FindingStatus, Run
from core.orchestrator import run_reproduce_finding
from executor.runner import Executor
from judges.ensemble import JudgeEnsemble
from scenario.finding import promote_scenario_result
from scenario.executor import run_scenario
from scenario.loader import load_scenarios
from scenario.reproducer import reproduce_scenario_finding
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from targets.fake import FakeLLMTarget


def _policy() -> PolicyEngine:
    return PolicyEngine.from_yaml("config/scope.example.yaml")


def _setup(tmp_path: Path, name: str = "scenario_finding.sqlite"):
    store = SQLiteStore(tmp_path / name)
    store.initialize()
    target = FakeLLMTarget()
    executor = Executor(policy=_policy(), target=target, store=store, target_id="fake-llm")
    run = Run(target_id="fake-llm", policy_hash=_policy().policy_hash, fingerprint="scenario")
    store.insert_run(run)
    judges = JudgeEnsemble.default()
    return store, executor, run, judges


def _cross_session_leak_scenario():
    return load_scenarios("scenario/suites/basic.yaml")[0]


def test_promote_scenario_result_only_promotes_flagged_steps(tmp_path: Path) -> None:
    store, executor, run, judges = _setup(tmp_path)
    scenario = _cross_session_leak_scenario()

    result = asyncio.run(run_scenario(scenario, run, executor, judges, store, target_url="https://ai.example.com/api/chat"))
    findings = promote_scenario_result(scenario, result, store)

    flagged_step_ids = {step.step_id for step in result.steps if step.judgement_passed}
    assert {f.reproduction_spec["step_id"] for f in findings} == flagged_step_ids
    for finding in findings:
        assert finding.reproduction_spec["type"] == "scenario"
        assert finding.reproduction_spec["scenario_id"] == scenario.id
        assert finding.reproduction_spec["steps"]  # full scenario snapshot, not just the flagged step
        assert finding.status == FindingStatus.CANDIDATE
        assert store.get_finding(finding.id) is not None  # actually persisted, not just returned


def test_promote_scenario_result_writes_step_evidence(tmp_path: Path) -> None:
    store, executor, run, judges = _setup(tmp_path)
    scenario = _cross_session_leak_scenario()
    result = asyncio.run(run_scenario(scenario, run, executor, judges, store, target_url="https://ai.example.com/api/chat"))

    findings = promote_scenario_result(scenario, result, store)
    assert findings
    for finding in findings:
        assert finding.evidence_ref
        with store.connect() as conn:
            row = conn.execute("select * from evidence where id = ?", (finding.evidence_ref,)).fetchone()
        assert row is not None
        assert row["kind"] == "scenario_response"


def test_reproduce_scenario_finding_confirms_when_attack_flags_and_control_does_not(tmp_path: Path) -> None:
    store, executor, run, judges = _setup(tmp_path)
    scenario = _cross_session_leak_scenario()
    control_run = Run(target_id="fake-llm", policy_hash=_policy().policy_hash, fingerprint="scenario_control")
    store.insert_run(control_run)

    outcome = asyncio.run(
        reproduce_scenario_finding(
            scenario, "leak", executor, judges, store, run, control_run, "https://ai.example.com/api/chat"
        )
    )

    assert outcome.attack_passed is True
    assert outcome.control_passed is True
    assert outcome.status == FindingStatus.CONFIRMED
    # full step trace preserved for both replays, not just the flagged step
    assert [s.step_id for s in outcome.result.steps] == ["leak", "replay"]
    assert [s.step_id for s in outcome.control_result.steps] == ["leak", "replay"]


def test_run_reproduce_finding_dispatches_scenario_findings_end_to_end(tmp_path: Path) -> None:
    store, executor, run, judges = _setup(tmp_path, "e2e.sqlite")
    scenario = _cross_session_leak_scenario()
    result = asyncio.run(run_scenario(scenario, run, executor, judges, store, target_url="https://ai.example.com/api/chat"))
    findings = promote_scenario_result(scenario, result, store)
    leak_finding = next(f for f in findings if f.reproduction_spec["step_id"] == "leak")

    outcome = asyncio.run(
        run_reproduce_finding(_policy(), [], store, leak_finding.id, target_kind="fake-llm")
    )

    assert outcome["finding_id"] == leak_finding.id
    assert outcome["reproduction"]["type"] == "scenario"
    assert outcome["reproduction"]["status"] == "confirmed"
    assert outcome["scenario_result"]["scenario_id"] == scenario.id


def test_run_reproduce_finding_minimize_flag_is_reported_as_unsupported_for_scenarios(tmp_path: Path) -> None:
    store, executor, run, judges = _setup(tmp_path, "minimize.sqlite")
    scenario = _cross_session_leak_scenario()
    result = asyncio.run(run_scenario(scenario, run, executor, judges, store, target_url="https://ai.example.com/api/chat"))
    findings = promote_scenario_result(scenario, result, store)
    leak_finding = next(f for f in findings if f.reproduction_spec["step_id"] == "leak")

    outcome = asyncio.run(
        run_reproduce_finding(_policy(), [], store, leak_finding.id, target_kind="fake-llm", minimize=True)
    )

    assert outcome["minimal_poc"] is None
    assert "not yet supported" in outcome["minimal_poc_note"]


def test_finding_reproduction_spec_round_trips_through_storage(tmp_path: Path) -> None:
    import json

    store, executor, run, judges = _setup(tmp_path, "roundtrip.sqlite")
    scenario = _cross_session_leak_scenario()
    result = asyncio.run(run_scenario(scenario, run, executor, judges, store, target_url="https://ai.example.com/api/chat"))
    findings = promote_scenario_result(scenario, result, store)
    finding = findings[0]

    reloaded = store.get_finding(finding.id)
    assert reloaded.reproduction_spec == finding.reproduction_spec
    json.dumps(reloaded.reproduction_spec)

    listed = store.list_findings([run.id])
    assert any(f.id == finding.id and f.reproduction_spec["type"] == "scenario" for f in listed)
