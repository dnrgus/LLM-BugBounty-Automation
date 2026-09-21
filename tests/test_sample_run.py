import asyncio
from pathlib import Path

from core.orchestrator import run_sample_pipeline
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from testcase.loader import load_testcases


def test_sample_pipeline_creates_candidate(tmp_path: Path) -> None:
    result = asyncio.run(
        run_sample_pipeline(
            PolicyEngine.from_yaml("config/scope.example.yaml"),
            load_testcases("testcase/suites/basic.yaml"),
            SQLiteStore(tmp_path / "sample.sqlite"),
        )
    )
    assert result["finding_count"] == 1
    assert result["reports"]


def test_sample_pipeline_accepts_fake_agent(tmp_path: Path) -> None:
    result = asyncio.run(
        run_sample_pipeline(
            PolicyEngine.from_yaml("config/scope.example.yaml"),
            load_testcases("testcase/suites/basic.yaml"),
            SQLiteStore(tmp_path / "agent.sqlite"),
            target_kind="fake-agent",
        )
    )
    assert result["target"] == "fake-agent"
    assert result["selected_testcases"] == ["LLM-PI-001", "LLM-SP-001"]
