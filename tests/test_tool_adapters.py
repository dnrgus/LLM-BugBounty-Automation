import json
from pathlib import Path

from adapters.llm.garak import GarakAdapter
from adapters.llm.promptfoo import PromptfooAdapter
from adapters.llm.pyrit import PyRITAdapter
from adapters.scanner.dalfox import DalfoxAdapter
from adapters.scanner.nuclei import NucleiAdapter
from adapters.secrets.trufflehog import TruffleHogAdapter
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


def test_pyrit_adapter_normalizes_adaptive_results() -> None:
    results = PyRITAdapter().parse_file(
        Path("tests/fixtures/tools/pyrit-results.json"),
        run_id="run_1",
        target_id="target_1",
        version="0.5",
    )
    assert len(results) == 1
    result = results[0]
    assert result.source.tool == "pyrit"
    assert result.category == "system_prompt_leak"
    assert result.testcase_id == "LLM-SP-001"
    assert result.detector_score == 0.91
    assert result.framework_tags["owasp_llm_2026"] == ["LLM02"]
    assert result.metadata["strategy"] == "crescendo"
    assert result.metadata["turn_count"] == 2


def test_nuclei_adapter_normalizes_findings() -> None:
    results = NucleiAdapter().parse_file(
        Path("tests/fixtures/tools/nuclei-results.jsonl"),
        run_id="run_1",
        target_id="target_1",
        version="3.0",
    )
    assert len(results) == 2
    high, info = results
    assert high.source.tool == "nuclei"
    assert high.category == "exposure"
    assert high.endpoint == "https://ai.example.com/.env"
    assert high.detector_score == 0.8
    assert info.detector_score == 0.1


def test_dalfox_adapter_filters_unconfirmed_and_normalizes() -> None:
    results = DalfoxAdapter().parse_file(
        Path("tests/fixtures/tools/dalfox-results.json"),
        run_id="run_1",
        target_id="target_1",
        version="2.9",
    )
    assert len(results) == 1
    result = results[0]
    assert result.source.tool == "dalfox"
    assert result.category == "xss"
    assert result.title == "Reflected XSS via 'q'"
    assert result.detector_score == 0.5
    assert result.metadata["cwe"] == "CWE-79"


def test_trufflehog_adapter_never_leaks_raw_secret() -> None:
    findings = TruffleHogAdapter().parse_file(
        Path("tests/fixtures/tools/trufflehog-results.jsonl"),
        run_id="run_1",
        target_id="target_1",
        version="3.80",
    )
    assert len(findings) == 2
    aws, slack = findings
    assert aws.source == "trufflehog"
    assert aws.detector == "AWS"
    assert aws.verified is True
    assert aws.location == "config/settings.py:42"
    assert aws.redacted_secret == "AKIA****************WXYZ"
    assert slack.verified is False

    dump = json.dumps([finding.to_dict() for finding in findings])
    assert "AKIAABCDEFGHIJKLMNOP" not in dump
    assert "xoxb-1234-5678-abcd" not in dump


def test_tool_doctor_snapshot_and_lock(tmp_path: Path) -> None:
    snapshot = check_tools("config/tools.yaml")
    assert snapshot["python"]
    assert any(tool["name"] == "promptfoo" for tool in snapshot["tools"])
    assert any(tool["name"] == "trufflehog" for tool in snapshot["tools"])
    lock_path = write_tool_lock(snapshot, tmp_path / "tool_versions.lock.yaml")
    assert lock_path.exists()
    assert "promptfoo" in lock_path.read_text(encoding="utf-8")
