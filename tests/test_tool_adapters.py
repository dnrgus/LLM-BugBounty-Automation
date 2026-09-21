from pathlib import Path

from adapters.llm.garak import GarakAdapter
from adapters.llm.promptfoo import PromptfooAdapter
from core.tool_doctor import check_tools, write_tool_lock


def test_promptfoo_adapter_normalizes_failed_results() -> None:
    results = PromptfooAdapter().parse_file(
        Path("tests/fixtures/tools/promptfoo-results.json"),
        run_id="run_1",
        target_id="target_1",
        version="1.0",
    )
    assert len(results) == 1
    result = results[0]
    assert result.source.tool == "promptfoo"
    assert result.category == "system_prompt_leak"
    assert result.testcase_id == "LLM-SP-001"
    assert result.detector_score == 0.93
    assert result.framework_tags["owasp_llm_2026"] == ["LLM02"]


def test_garak_adapter_normalizes_findings() -> None:
    results = GarakAdapter().parse_file(
        Path("tests/fixtures/tools/garak-results.jsonl"),
        run_id="run_1",
        target_id="target_1",
        version="0.1",
    )
    assert len(results) == 1
    result = results[0]
    assert result.source.tool == "garak"
    assert result.title == "leak.SystemPrompt / canary.String"
    assert result.detector_score == 0.88
    assert result.framework_tags["mitre_atlas"] == ["AML.T0057"]


def test_tool_doctor_snapshot_and_lock(tmp_path: Path) -> None:
    snapshot = check_tools("config/tools.yaml")
    assert snapshot["python"]
    assert any(tool["name"] == "promptfoo" for tool in snapshot["tools"])
    assert any(tool["name"] == "trufflehog" for tool in snapshot["tools"])
    lock_path = write_tool_lock(snapshot, tmp_path / "tool_versions.lock.yaml")
    assert lock_path.exists()
    assert "promptfoo" in lock_path.read_text(encoding="utf-8")
