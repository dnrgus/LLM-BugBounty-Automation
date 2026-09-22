from __future__ import annotations

from pathlib import Path
import json

from core.models import Finding, Judgement, Run
from reproduction.reproducer import ReproductionOutcome
from testcase.schema import Testcase

_STATUS_LABELS = {
    "confirmed": "확정됨",
    "unstable": "불안정",
    "rejected": "기각됨",
    "candidate": "후보",
}

# P4.1-E (roadmap v4.1.0 Dynamic Validation Expansion): what a CONFIRMED
# result from each validator type actually means, kept next to the
# report so "정적 근거/동적 검증" sections never overclaim beyond what
# the validator itself checked (validation/finding_adapter.py owns the
# canonical copy of this text; duplicated here only because reporter.py
# has no other dependency on validation/*).
_LIMITATIONS_BY_VALIDATOR_TYPE = {
    "endpoint": "이 검증은 후보 엔드포인트가 실제로 살아있고 도달 가능한지만 확인하며, 그 자체로 취약점을 의미하지 않습니다.",
    "auth": "명시적으로 제공된 fixture/env/browser-session 인증 컨텍스트 두 개가 동일한 응답 구조를 관측했는지만 확인하며, "
    "추측하거나 탈취한 자격증명으로부터 도출된 결과가 아닙니다.",
    "dataflow": "무해한 correlation token이 관측 가능한 지점에 반사(reflect)되었는지만 확인하며, 정적으로 추적된 특정 "
    "sink에 실제로 도달했다는 의미는 아니고 sink의 실제 payload/동작은 실행되지 않았습니다.",
}


def _static_dynamic_sections(finding: Finding) -> list[str]:
    """Only emitted when the finding carries static/dynamic provenance
    (validation/finding_adapter.py or the legacy static-candidate
    correlation path) -- a plain testcase-driven finding's report is
    unchanged.
    """
    if not finding.static_candidate_id:
        return []
    validator_type = str(finding.reproduction_spec.get("validator_type", finding.category))
    limitation = _LIMITATIONS_BY_VALIDATOR_TYPE.get(validator_type)
    lines = [
        "",
        "## 정적 근거 (Static Evidence)",
        "",
        f"- Static Candidate ID: `{finding.static_candidate_id}`",
        "",
        "## 동적 검증 (Dynamic Validation)",
        "",
        f"- Validator: {validator_type}",
        f"- Validation Task IDs: {', '.join(finding.validation_task_ids) or '(none)'}",
        f"- Validation Status: {finding.validation_status or '(none)'}",
    ]
    if limitation:
        lines += ["", "## 제한사항 (Limitations)", "", limitation]
    return lines


def write_markdown_report(
    directory: Path,
    run: Run,
    testcase: Testcase,
    finding: Finding,
    judgement: Judgement,
    evidence_path: Path,
    reproduction: ReproductionOutcome | None = None,
    evidence_metadata: dict[str, object] | None = None,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{finding.id}.md"
    status_value = finding.status.value
    status_label = _STATUS_LABELS.get(status_value, status_value)
    path.write_text(
        "\n".join(
            [
                f"# {finding.title}",
                "",
                f"- 상태: {status_label} ({status_value})",
                f"- 심각도: {finding.severity}",
                f"- 신뢰도: {finding.confidence:.2f}",
                f"- 카테고리: {finding.category}",
                f"- 테스트케이스: {testcase.id}",
                f"- Run: {run.id}",
                f"- 실행 환경 Fingerprint: `{run.fingerprint}`",
                f"- Evidence: `{evidence_path}`",
                f"- 재현율: {_reproduction_rate(reproduction)}",
                f"- Negative Control: {_control_status(reproduction)}",
                "",
                "## 요약",
                "",
                "이 파이프라인은 결정론적(deterministic) Judge와 Negative Control 검증을 거쳐 이 finding을 재현했습니다.",
                "",
                "## 재현 절차",
                "",
                "1. 테스트케이스 프롬프트를 불러옵니다.",
                "2. 대상 URL이 Scope와 Program Policy를 통과하는지 검증합니다.",
                "3. 대상 세션에 프롬프트를 전송합니다.",
                "4. 응답을 결정론적 Judge로 평가합니다.",
                "5. 재현 시도를 반복하고 Negative Control 결과와 비교합니다.",
                "",
                "## Prompt",
                "",
                "```text",
                testcase.prompt.strip(),
                "```",
                "",
                "## Judge 판정",
                "",
                judgement.reason,
                "",
                "## Evidence 메타데이터",
                "",
                "```json",
                json.dumps(evidence_metadata or {}, indent=2, sort_keys=True),
                "```",
                *_static_dynamic_sections(finding),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def write_json_report(
    directory: Path,
    run: Run,
    testcase: Testcase,
    finding: Finding,
    judgement: Judgement,
    evidence_metadata: dict[str, object],
    reproduction: ReproductionOutcome | None = None,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{finding.id}.json"
    payload = {
        "title": finding.title,
        "status": finding.status.value,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "category": finding.category,
        "testcase_id": testcase.id,
        "run_id": run.id,
        "environment_fingerprint": run.fingerprint,
        "prompt": testcase.prompt,
        "judgement": {
            "type": judgement.judge_type,
            "passed": judgement.passed,
            "score": judgement.score,
            "reason": judgement.reason,
        },
        "reproduction": None if reproduction is None else {
            "attempts": reproduction.attempts,
            "successes": reproduction.successes,
            "threshold": reproduction.threshold,
            "success_rate": reproduction.success_rate,
            "control_passed": reproduction.control_passed,
            "status": reproduction.status.value,
        },
        "evidence": evidence_metadata,
    }
    if finding.static_candidate_id:
        validator_type = str(finding.reproduction_spec.get("validator_type", finding.category))
        payload["static_evidence"] = {"static_candidate_id": finding.static_candidate_id}
        payload["dynamic_validation"] = {
            "validator_type": validator_type,
            "validation_task_ids": finding.validation_task_ids,
            "validation_status": finding.validation_status,
        }
        limitation = _LIMITATIONS_BY_VALIDATOR_TYPE.get(validator_type)
        if limitation:
            payload["limitations"] = limitation
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _reproduction_rate(reproduction: ReproductionOutcome | None) -> str:
    if reproduction is None:
        return "실행 안 함"
    return f"{reproduction.successes}/{reproduction.attempts} ({reproduction.success_rate:.2f})"


def _control_status(reproduction: ReproductionOutcome | None) -> str:
    if reproduction is None:
        return "실행 안 함"
    return "통과" if reproduction.control_passed else "실패"
