"""P3.3-3 Dynamic Validator + Correlated Finding (roadmap v3.3.0 Static -> Dynamic Validation).

Reuses the existing fake-llm target (this project's own stand-in for a
"local vulnerable app") and the existing fake-agent target for a
"negative" control-shaped case, per the roadmap's required test list
(local vulnerable apps, negative apps, repeated runs, session reset).
"""

import asyncio
from pathlib import Path

from attack_surface.models import AttackSurfaceItem
from correlation.resolver import resolve_entities
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from testcase.loader import load_testcases
from validation.executor import run_dynamic_validation
from validation.planner import ValidationPlan


def _source_endpoint(path: str, method: str = "GET") -> AttackSurfaceItem:
    return AttackSurfaceItem(source_type="source", asset_type="endpoint", location=path, metadata={"method": method})


def _live_endpoint(url: str, method: str = "GET") -> AttackSurfaceItem:
    return AttackSurfaceItem(source_type="live", asset_type="endpoint", location=url, metadata={"method": method})


def _policy() -> PolicyEngine:
    return PolicyEngine.from_yaml("config/scope.example.yaml")


def _testcases():
    return load_testcases("testcase/suites/basic.yaml")


def _llm_item(file: str = "app.py") -> AttackSurfaceItem:
    return AttackSurfaceItem(source_type="source", asset_type="llm", location=file, metadata={"file": file})


def _executable_plan(candidate_id: str) -> ValidationPlan:
    return ValidationPlan(candidate_id, "llm", "executable", "test fixture plan")


def _match():
    source = _source_endpoint("/api/chat")
    live = _live_endpoint("https://ai.example.com/api/chat")
    return resolve_entities([source], [live])[0]


def test_run_dynamic_validation_runs_llm_core_pack_and_correlates_a_confirmed_finding(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "dynval.sqlite")
    item = _llm_item()
    plan = _executable_plan(item.id)
    match = _match()

    outcome = asyncio.run(
        run_dynamic_validation(item, plan, match, _policy(), _testcases(), store, target_kind="fake-llm")
    )

    assert outcome.status == "ran"
    assert outcome.correlated_findings
    confirmed = [cf for cf in outcome.correlated_findings if cf.finding.status.value == "confirmed"]
    assert confirmed
    correlated = confirmed[0]
    assert correlated.static_candidate.id == item.id
    assert correlated.finding.reproduction_spec["origin"] == ["static", "dynamic"]
    assert correlated.finding.reproduction_spec["static_candidate_id"] == item.id
    assert correlated.finding.reproduction_spec["entity_match_basis"] == match.basis


def test_run_dynamic_validation_persists_the_origin_tag_to_storage(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "dynval.sqlite")
    item = _llm_item()
    plan = _executable_plan(item.id)
    match = _match()

    outcome = asyncio.run(
        run_dynamic_validation(item, plan, match, _policy(), _testcases(), store, target_kind="fake-llm")
    )
    finding_id = outcome.correlated_findings[0].finding.id

    reloaded = store.get_finding(finding_id)
    assert reloaded.reproduction_spec["origin"] == ["static", "dynamic"]


def test_review_only_plan_is_not_run(tmp_path: Path) -> None:
    item = _llm_item()
    plan = ValidationPlan(item.id, "llm", "review_only", "no live match yet")
    match = _match()
    store = SQLiteStore(tmp_path / "dynval.sqlite")
    outcome = asyncio.run(
        run_dynamic_validation(item, plan, match, _policy(), _testcases(), store, target_kind="fake-llm")
    )
    assert outcome.status == "not_run"
    assert outcome.correlated_findings == []


def test_endpoint_asset_type_has_no_dynamic_executor_yet(tmp_path: Path) -> None:
    endpoint_item = AttackSurfaceItem(source_type="source", asset_type="endpoint", location="/api/chat", metadata={})
    plan = ValidationPlan(endpoint_item.id, "endpoint", "executable", "matched live endpoint")
    match = _match()
    store = SQLiteStore(tmp_path / "dynval.sqlite")
    outcome = asyncio.run(
        run_dynamic_validation(endpoint_item, plan, match, _policy(), _testcases(), store, target_kind="fake-llm")
    )
    assert outcome.status == "not_run"
    assert "no dynamic executor" in outcome.detail


def test_negative_control_fake_agent_target_produces_no_llm_core_findings(tmp_path: Path) -> None:
    # fake-agent doesn't support the plain chat capability llm_core's
    # testcases require, so the negative case here is "nothing runs",
    # mirroring the roadmap's "negative apps" requirement.
    store = SQLiteStore(tmp_path / "dynval.sqlite")
    item = _llm_item()
    plan = _executable_plan(item.id)
    match = _match()
    outcome = asyncio.run(
        run_dynamic_validation(item, plan, match, _policy(), _testcases(), store, target_kind="fake-agent")
    )
    assert outcome.status == "ran"
    assert all(cf.finding.status.value != "confirmed" for cf in outcome.correlated_findings)


def test_repeated_runs_produce_independent_findings_without_session_contamination(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "dynval.sqlite")
    item = _llm_item()
    plan = _executable_plan(item.id)
    match = _match()

    first = asyncio.run(
        run_dynamic_validation(item, plan, match, _policy(), _testcases(), store, target_kind="fake-llm")
    )
    second = asyncio.run(
        run_dynamic_validation(item, plan, match, _policy(), _testcases(), store, target_kind="fake-llm")
    )

    first_ids = {cf.finding.id for cf in first.correlated_findings}
    second_ids = {cf.finding.id for cf in second.correlated_findings}
    assert first_ids.isdisjoint(second_ids)
    assert any(cf.finding.status.value == "confirmed" for cf in first.correlated_findings)
    assert any(cf.finding.status.value == "confirmed" for cf in second.correlated_findings)


def test_dynamic_validation_outcome_to_dict_is_json_serializable(tmp_path: Path) -> None:
    import json

    store = SQLiteStore(tmp_path / "dynval.sqlite")
    item = _llm_item()
    plan = _executable_plan(item.id)
    match = _match()
    outcome = asyncio.run(
        run_dynamic_validation(item, plan, match, _policy(), _testcases(), store, target_kind="fake-llm")
    )
    json.dumps(outcome.to_dict())
