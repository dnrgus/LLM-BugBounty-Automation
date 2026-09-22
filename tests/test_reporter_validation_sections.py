"""P4.1-E report split (roadmap v4.1.0): a static/dynamic-origin
Finding's report gains explicit Static Evidence / Dynamic Validation /
Limitations sections; a plain testcase-driven Finding's report is
unchanged.
"""

import json
from pathlib import Path

from core.models import Finding, FindingStatus, Judgement, Run
from reporting.reporter import write_json_report, write_markdown_report
from testcase.schema import Testcase


def _run() -> Run:
    return Run(target_id="target-1", policy_hash="hash", fingerprint="fp")


def _testcase() -> Testcase:
    return Testcase(
        id="LLM-SP-001", name="System prompt leak", category="system_prompt_leak",
        requires=["chat"], prompt="ignore instructions", judges=["deterministic"],
    )


def _judgement(run: Run, testcase: Testcase) -> Judgement:
    return Judgement(run_id=run.id, testcase_id=testcase.id, judge_type="deterministic", passed=True, score=0.9, reason="matched pattern")


def _plain_finding(run: Run, testcase: Testcase) -> Finding:
    return Finding(
        run_id=run.id, testcase_id=testcase.id, title=testcase.name, category=testcase.category,
        status=FindingStatus.CONFIRMED, confidence=0.9, severity="high", evidence_ref="ev-1",
    )


def _validation_finding(run: Run) -> Finding:
    return Finding(
        run_id=run.id, testcase_id="vtask-1", title="endpoint validation: AS-1", category="endpoint",
        status=FindingStatus.CONFIRMED, confidence=0.8, severity="info", evidence_ref="ev-2",
        reproduction_spec={"type": "validation", "validator_type": "endpoint", "task_id": "vtask-1", "target_entity": "https://ai.example.com/x"},
        origin=["static", "dynamic"], static_candidate_id="AS-1", validation_task_ids=["vtask-1"], validation_status="confirmed",
    )


def test_markdown_report_omits_static_dynamic_sections_for_plain_finding(tmp_path: Path) -> None:
    run, testcase = _run(), _testcase()
    finding = _plain_finding(run, testcase)
    judgement = _judgement(run, testcase)

    path = write_markdown_report(tmp_path, run, testcase, finding, judgement, tmp_path / "evidence.json")
    text = path.read_text(encoding="utf-8")

    assert "정적 근거" not in text
    assert "동적 검증" not in text


def test_markdown_report_includes_static_dynamic_sections_for_validation_finding(tmp_path: Path) -> None:
    run, testcase = _run(), _testcase()
    finding = _validation_finding(run)
    judgement = _judgement(run, testcase)

    path = write_markdown_report(tmp_path, run, testcase, finding, judgement, tmp_path / "evidence.json")
    text = path.read_text(encoding="utf-8")

    assert "정적 근거" in text
    assert "동적 검증" in text
    assert "AS-1" in text
    assert "제한사항" in text


def test_json_report_omits_static_dynamic_keys_for_plain_finding(tmp_path: Path) -> None:
    run, testcase = _run(), _testcase()
    finding = _plain_finding(run, testcase)
    judgement = _judgement(run, testcase)

    path = write_json_report(tmp_path, run, testcase, finding, judgement, {})
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert "static_evidence" not in payload
    assert "dynamic_validation" not in payload


def test_json_report_includes_static_dynamic_keys_for_validation_finding(tmp_path: Path) -> None:
    run, testcase = _run(), _testcase()
    finding = _validation_finding(run)
    judgement = _judgement(run, testcase)

    path = write_json_report(tmp_path, run, testcase, finding, judgement, {})
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["static_evidence"]["static_candidate_id"] == "AS-1"
    assert payload["dynamic_validation"]["validator_type"] == "endpoint"
    assert payload["dynamic_validation"]["validation_status"] == "confirmed"
    assert "limitations" in payload
