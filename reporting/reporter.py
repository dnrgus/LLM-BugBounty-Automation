from __future__ import annotations

from pathlib import Path

from core.models import Finding, Judgement, Run
from testcase.schema import Testcase


def write_markdown_report(
    directory: Path,
    run: Run,
    testcase: Testcase,
    finding: Finding,
    judgement: Judgement,
    evidence_path: Path,
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
                "",
                "## Summary",
                "",
                "The offline validation pipeline detected a candidate issue using the bundled fake target.",
                "",
                "## Steps to Reproduce",
                "",
                "1. Load the testcase prompt.",
                "2. Validate the target URL against scope and program policy.",
                "3. Send the prompt to the target session.",
                "4. Evaluate the response with deterministic judges.",
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
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return path

