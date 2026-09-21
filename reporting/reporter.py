from __future__ import annotations

from pathlib import Path
import json

from core.models import Finding, Judgement, Run
from reproduction.reproducer import ReproductionOutcome
from testcase.schema import Testcase


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
    path.write_text(
        "\n".join(
            [
                f"# {finding.title}",
                "",
                f"- Status: {finding.status.value}",
                f"- Severity: {finding.severity}",
                f"- Confidence: {finding.confidence:.2f}",
                f"- Category: {finding.category}",
                f"- Testcase: {testcase.id}",
                f"- Run: {run.id}",
                f"- Environment Fingerprint: `{run.fingerprint}`",
                f"- Evidence: `{evidence_path}`",
                f"- Reproduction Rate: {_reproduction_rate(reproduction)}",
                f"- Control: {_control_status(reproduction)}",
                "",
                "## Summary",
                "",
                "The validation pipeline reproduced this finding using deterministic judges and control checks.",
                "",
                "## Steps to Reproduce",
                "",
                "1. Load the testcase prompt.",
                "2. Validate the target URL against scope and program policy.",
                "3. Send the prompt to the target session.",
                "4. Evaluate the response with deterministic judges.",
                "5. Repeat reproduction attempts and compare with the negative control.",
                "",
                "## Prompt",
                "",
                "```text",
                testcase.prompt.strip(),
                "```",
                "",
                "## Judgement",
                "",
                judgement.reason,
                "",
                "## Evidence Metadata",
                "",
                "```json",
                json.dumps(evidence_metadata or {}, indent=2, sort_keys=True),
                "```",
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
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _reproduction_rate(reproduction: ReproductionOutcome | None) -> str:
    if reproduction is None:
        return "not run"
    return f"{reproduction.successes}/{reproduction.attempts} ({reproduction.success_rate:.2f})"


def _control_status(reproduction: ReproductionOutcome | None) -> str:
    if reproduction is None:
        return "not run"
    return "passed" if reproduction.control_passed else "failed"
