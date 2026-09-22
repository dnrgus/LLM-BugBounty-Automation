"""P3.4-1 Checkpoint / Resume (roadmap v3.4.0 Production Hardening)."""

import asyncio
from dataclasses import replace
from pathlib import Path

import pytest

from core.checkpoint import ConfigFingerprintMismatchError, compute_config_fingerprint
from core.orchestrator import run_sample_pipeline
from core.profile import load_profile
from scope.policy import PolicyEngine
from storage.run_state import RunStateStore
from storage.sqlite import SQLiteStore
from testcase.loader import load_testcases


def _policy() -> PolicyEngine:
    return PolicyEngine.from_yaml("config/scope.example.yaml")


def _testcases():
    return load_testcases("testcase/suites/basic.yaml")


def test_compute_config_fingerprint_is_stable_and_order_independent() -> None:
    a = compute_config_fingerprint({"x": 1, "y": [1, 2]})
    b = compute_config_fingerprint({"y": [1, 2], "x": 1})
    c = compute_config_fingerprint({"x": 1, "y": [2, 1]})
    assert a == b
    assert a != c


def test_run_state_store_fresh_start_has_no_completed_steps(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "state.sqlite")
    run_state = RunStateStore(store)
    decision = run_state.start_or_resume("run_A", "fp1")
    assert decision.is_resume is False
    assert decision.completed_step_ids == frozenset()


def test_run_state_store_resume_returns_previously_completed_steps(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "state.sqlite")
    run_state = RunStateStore(store)
    run_state.start_or_resume("run_A", "fp1")
    run_state.mark_step_completed("run_A", "case-1")

    decision = run_state.start_or_resume("run_A", "fp1")
    assert decision.is_resume is True
    assert decision.completed_step_ids == frozenset({"case-1"})


def test_run_state_store_rejects_a_changed_configuration(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "state.sqlite")
    run_state = RunStateStore(store)
    run_state.start_or_resume("run_A", "fp1")

    with pytest.raises(ConfigFingerprintMismatchError):
        run_state.start_or_resume("run_A", "fp2-different")


def test_insert_run_is_idempotent_for_the_same_run_id(tmp_path: Path) -> None:
    from core.models import Run

    store = SQLiteStore(tmp_path / "state.sqlite")
    store.initialize()
    run = Run(target_id="t", policy_hash="h", fingerprint="f", id="run_fixed")
    store.insert_run(run)
    store.insert_run(run)  # must not raise an integrity error
    with store.connect() as conn:
        count = conn.execute("select count(*) as n from runs where id = ?", ("run_fixed",)).fetchone()["n"]
    assert count == 1


def test_kill_and_resume_skips_completed_steps_and_does_not_touch_a_broken_target(tmp_path: Path, monkeypatch) -> None:
    import core.orchestrator as orchestrator_module
    from targets.errors import TargetConnectionError
    from targets.fake import FakeLLMTarget

    store = SQLiteStore(tmp_path / "resume.sqlite")

    first = asyncio.run(
        run_sample_pipeline(_policy(), _testcases(), store, target_kind="fake-llm", resume_run_id="run_resume_1")
    )
    assert first["executed_testcases"] == ["LLM-PI-001", "LLM-SP-001"]
    assert first["finding_count"] == 1

    class AlwaysFailingTarget(FakeLLMTarget):
        async def send(self, prompt, session=None):
            raise TargetConnectionError("this target must never be called on a full resume")

    monkeypatch.setattr(orchestrator_module, "create_target", lambda kind, config=None: AlwaysFailingTarget())

    second = asyncio.run(
        run_sample_pipeline(_policy(), _testcases(), store, target_kind="fake-llm", resume_run_id="run_resume_1")
    )
    assert second["run_id"] == first["run_id"]
    assert second["executed_testcases"] == ["LLM-PI-001", "LLM-SP-001"]
    assert second["finding_count"] == 1  # cumulative, from storage -- not re-derived by re-running


def test_kill_and_resume_after_a_budget_cutoff_completes_the_remaining_steps(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "resume_budget.sqlite")
    cut_short_profile = replace(load_profile("quick", "config/pipeline.yaml"), budget_max_requests=1)

    first = asyncio.run(
        run_sample_pipeline(
            _policy(), _testcases(), store, target_kind="fake-llm",
            profile=cut_short_profile, resume_run_id="run_resume_2",
        )
    )
    assert first["executed_testcases"] == ["LLM-PI-001"]  # cut off by budget before LLM-SP-001

    full_profile = load_profile("quick", "config/pipeline.yaml")
    second = asyncio.run(
        run_sample_pipeline(
            _policy(), _testcases(), store, target_kind="fake-llm",
            profile=full_profile, resume_run_id="run_resume_2",
        )
    )
    assert second["executed_testcases"] == ["LLM-PI-001", "LLM-SP-001"]
    assert second["finding_count"] == 1


def test_resuming_with_a_changed_testcase_suite_is_rejected(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "resume_mismatch.sqlite")
    asyncio.run(
        run_sample_pipeline(_policy(), _testcases(), store, target_kind="fake-llm", resume_run_id="run_resume_3")
    )

    changed_testcases = [replace(case, prompt=case.prompt + " (modified)") for case in _testcases()]
    with pytest.raises(ConfigFingerprintMismatchError):
        asyncio.run(
            run_sample_pipeline(
                _policy(), changed_testcases, store, target_kind="fake-llm", resume_run_id="run_resume_3"
            )
        )


def test_omitting_resume_run_id_is_unaffected(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "no_resume.sqlite")
    first = asyncio.run(run_sample_pipeline(_policy(), _testcases(), store, target_kind="fake-llm"))
    second = asyncio.run(run_sample_pipeline(_policy(), _testcases(), store, target_kind="fake-llm"))
    assert first["run_id"] != second["run_id"]  # each call still gets its own fresh run_id
