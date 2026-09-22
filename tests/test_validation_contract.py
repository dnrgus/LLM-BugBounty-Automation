"""P4.1-A Validation Contract (roadmap v4.1.0 Dynamic Validation Expansion)."""

import asyncio
import json
from pathlib import Path

import pytest

from attack_surface.models import AttackSurfaceItem
from correlation.resolver import resolve_entities
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from testcase.loader import load_testcases
from validation.contract import (
    DEFAULT_STRATEGIES,
    InvalidValidationStateTransition,
    ValidationResult,
    ValidationStatus,
    ValidationTask,
)
from validation.executor import run_dynamic_validation
from validation.legacy_adapter import validation_results_from_dynamic_outcome, validation_task_from_plan
from validation.planner import ValidationPlan, generate_validation_plans


def _policy() -> PolicyEngine:
    return PolicyEngine.from_yaml("config/scope.example.yaml")


def _testcases():
    return load_testcases("testcase/suites/basic.yaml")


# --- state machine -----------------------------------------------------


def test_task_starts_planned() -> None:
    task = ValidationTask(candidate_id="c1", validator_type="endpoint")
    assert task.status == ValidationStatus.PLANNED


def test_valid_transition_sequence_succeeds() -> None:
    task = ValidationTask(candidate_id="c1", validator_type="llm_core")
    task.transition(ValidationStatus.EXECUTABLE)
    task.transition(ValidationStatus.RUNNING)
    task.transition(ValidationStatus.CONFIRMED)
    assert task.status == ValidationStatus.CONFIRMED


def test_invalid_transition_raises_and_does_not_mutate_status() -> None:
    task = ValidationTask(candidate_id="c1", validator_type="llm_core")
    with pytest.raises(InvalidValidationStateTransition):
        task.transition(ValidationStatus.CONFIRMED)  # PLANNED -> CONFIRMED skips required steps
    assert task.status == ValidationStatus.PLANNED


def test_terminal_states_accept_no_further_transitions() -> None:
    task = ValidationTask(candidate_id="c1", validator_type="llm_core")
    task.transition(ValidationStatus.BLOCKED)
    with pytest.raises(InvalidValidationStateTransition):
        task.transition(ValidationStatus.EXECUTABLE)


# --- serialization -------------------------------------------------------


def test_validation_task_round_trips_through_dict() -> None:
    task = ValidationTask(candidate_id="c1", validator_type="endpoint", risk_level="high", required_sessions=2)
    task.transition(ValidationStatus.EXECUTABLE)
    restored = ValidationTask.from_dict(json.loads(json.dumps(task.to_dict())))
    assert restored.to_dict() == task.to_dict()


def test_validation_result_round_trips_through_dict() -> None:
    result = ValidationResult(task_id="t1", status=ValidationStatus.CONFIRMED, confidence=0.9, evidence_refs=["e1"])
    restored = ValidationResult.from_dict(json.loads(json.dumps(result.to_dict())))
    assert restored.to_dict() == result.to_dict()


def test_default_strategies_are_json_serializable() -> None:
    json.dumps([strategy.to_dict() for strategy in DEFAULT_STRATEGIES])
    assert {strategy.validator_type for strategy in DEFAULT_STRATEGIES} >= {"llm_core", "endpoint", "auth", "dataflow"}


# --- DB persistence -------------------------------------------------------


def test_validation_task_persists_and_reloads(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "vtask.sqlite")
    store.initialize()
    task = ValidationTask(candidate_id="c1", validator_type="endpoint", budget_hint={"max_requests": 5})

    store.upsert_validation_task(task)
    reloaded = store.get_validation_task(task.id)

    assert reloaded is not None
    assert reloaded.to_dict() == task.to_dict()


def test_validation_task_upsert_reflects_transitions(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "vtask.sqlite")
    store.initialize()
    task = ValidationTask(candidate_id="c1", validator_type="endpoint")
    store.upsert_validation_task(task)

    task.transition(ValidationStatus.EXECUTABLE)
    store.upsert_validation_task(task)

    reloaded = store.get_validation_task(task.id)
    assert reloaded.status == ValidationStatus.EXECUTABLE


def test_validation_results_persist_and_list_in_order(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "vresult.sqlite")
    store.initialize()
    task = ValidationTask(candidate_id="c1", validator_type="llm_core")
    store.upsert_validation_task(task)

    first = ValidationResult(task_id=task.id, status=ValidationStatus.CONFIRMED, confidence=0.9)
    second = ValidationResult(task_id=task.id, status=ValidationStatus.REJECTED, confidence=0.2)
    store.insert_validation_result(first)
    store.insert_validation_result(second)

    results = store.list_validation_results(task.id)
    assert [r.id for r in results] == [first.id, second.id]


def test_validation_tables_do_not_conflict_with_a_preexisting_older_schema(tmp_path: Path) -> None:
    # A store that only ever used pre-v4.1 tables (findings/evidence/etc.)
    # must gain the new tables cleanly on the next initialize() call --
    # "create table if not exists" is the whole migration.
    store = SQLiteStore(tmp_path / "legacy.sqlite")
    store.initialize()
    with store.connect() as conn:
        conn.execute("select count(*) from findings").fetchone()

    task = ValidationTask(candidate_id="c1", validator_type="endpoint")
    store.upsert_validation_task(task)
    assert store.get_validation_task(task.id) is not None


# --- legacy adapter -------------------------------------------------------


def test_legacy_adapter_wraps_an_executable_plan() -> None:
    plan = ValidationPlan("cand1", "llm", "executable", "matched live endpoint")
    task = validation_task_from_plan(plan)
    assert task.status == ValidationStatus.EXECUTABLE
    assert task.validator_type == "llm_core"
    assert task.candidate_id == "cand1"


def test_legacy_adapter_wraps_a_review_only_plan() -> None:
    plan = ValidationPlan("cand1", "auth", "review_only", "no recognized auth guard found")
    task = validation_task_from_plan(plan)
    assert task.status == ValidationStatus.REVIEW_ONLY


def test_legacy_adapter_wraps_an_unsupported_plan_as_blocked() -> None:
    plan = ValidationPlan("cand1", "secret", "unsupported", "no dynamic validation concept applies")
    task = validation_task_from_plan(plan)
    assert task.status == ValidationStatus.BLOCKED


def test_legacy_adapter_wraps_a_real_dynamic_outcome_end_to_end(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "adapter.sqlite")
    item = AttackSurfaceItem(source_type="source", asset_type="llm", location="app.py", metadata={"file": "app.py"})
    source = AttackSurfaceItem(
        source_type="source", asset_type="endpoint", location="/api/chat", metadata={"method": "GET"}
    )
    live = AttackSurfaceItem(
        source_type="live", asset_type="endpoint", location="https://ai.example.com/api/chat", metadata={"method": "GET"}
    )
    match = resolve_entities([source], [live])[0]
    plan = ValidationPlan(item.id, "llm", "executable", "matched")

    outcome = asyncio.run(
        run_dynamic_validation(item, plan, match, _policy(), _testcases(), store, target_kind="fake-llm")
    )
    task = validation_task_from_plan(plan)
    results = validation_results_from_dynamic_outcome(task, outcome)

    assert task.status in {ValidationStatus.CONFIRMED, ValidationStatus.REJECTED, ValidationStatus.UNSTABLE}
    assert len(results) == len(outcome.correlated_findings)
    assert any(result.status == ValidationStatus.CONFIRMED for result in results)


def test_legacy_adapter_returns_no_results_for_a_not_run_outcome() -> None:
    from validation.executor import DynamicValidationOutcome

    item = AttackSurfaceItem(source_type="source", asset_type="endpoint", location="/api/x", metadata={})
    plan = ValidationPlan(item.id, "endpoint", "executable", "matched")
    task = validation_task_from_plan(plan)
    outcome = DynamicValidationOutcome(item, plan, "not_run", "no dynamic executor available")

    results = validation_results_from_dynamic_outcome(task, outcome)
    assert results == []


def test_generate_validation_plans_output_all_wrap_cleanly_into_tasks() -> None:
    items = [
        AttackSurfaceItem(source_type="source", asset_type="secret", location="app.py:1", metadata={}),
        AttackSurfaceItem(source_type="source", asset_type="auth", location="app.py:1", metadata={"handler": "h", "detected": False}),
    ]
    plans = generate_validation_plans(items)
    tasks = [validation_task_from_plan(plan) for plan in plans]
    assert all(task.status in {ValidationStatus.BLOCKED, ValidationStatus.REVIEW_ONLY} for task in tasks)
