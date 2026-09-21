import asyncio
from pathlib import Path

import pytest

from core.orchestrator import run_reproduce_finding, run_sample_pipeline
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from testcase.loader import load_testcases


def _policy() -> PolicyEngine:
    return PolicyEngine.from_yaml("config/scope.example.yaml")


def _testcases():
    return load_testcases("testcase/suites/basic.yaml")


def _seed_a_confirmed_finding(store: SQLiteStore) -> str:
    result = asyncio.run(run_sample_pipeline(_policy(), _testcases(), store, target_kind="fake-llm"))
    return result["clusters"][0]["finding_ids"][0]


def test_run_reproduce_finding_replays_the_stored_prompt(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "reproduce.sqlite")
    finding_id = _seed_a_confirmed_finding(store)
    result = asyncio.run(run_reproduce_finding(_policy(), _testcases(), store, finding_id, target_kind="fake-llm"))
    assert result["finding_id"] == finding_id
    assert result["testcase_id"] == "LLM-SP-001"
    assert result["original_status"] == "confirmed"
    assert result["reproduction"]["status"] == "confirmed"
    assert "minimal_poc" not in result


def test_run_reproduce_finding_with_minimize_attaches_poc_and_evidence(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "reproduce_minimize.sqlite")
    finding_id = _seed_a_confirmed_finding(store)
    result = asyncio.run(
        run_reproduce_finding(_policy(), _testcases(), store, finding_id, target_kind="fake-llm", minimize=True)
    )
    assert result["minimal_poc"]["minimized_prompt"] == "CANARY-SECRET-123"
    assert result["minimal_poc_evidence_id"]
    with store.connect() as conn:
        row = conn.execute(
            "select kind from evidence where id = ?", (result["minimal_poc_evidence_id"],)
        ).fetchone()
    assert row["kind"] == "minimal_poc"


def test_run_reproduce_finding_raises_for_unknown_finding_id(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "reproduce_missing.sqlite")
    store.initialize()
    with pytest.raises(ValueError, match="finding not found"):
        asyncio.run(run_reproduce_finding(_policy(), _testcases(), store, "finding_missing", target_kind="fake-llm"))


def test_run_reproduce_finding_raises_when_seed_testcase_not_in_suite(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "reproduce_no_suite.sqlite")
    finding_id = _seed_a_confirmed_finding(store)
    with pytest.raises(ValueError, match="not found in the provided"):
        asyncio.run(run_reproduce_finding(_policy(), [], store, finding_id, target_kind="fake-llm"))
