from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools.adapters.base import NormalizedResult, ToolSource, safe_float


class PromptfooAdapter:
    tool = "promptfoo"

    def parse_file(
        self,
        path: Path | str,
        run_id: str,
        target_id: str,
        version: str | None = None,
    ) -> list[NormalizedResult]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.parse(data, run_id=run_id, target_id=target_id, version=version, raw_artifact_ref=str(path))

    def parse(
        self,
        data: dict[str, Any],
        run_id: str,
        target_id: str,
        version: str | None = None,
        raw_artifact_ref: str | None = None,
    ) -> list[NormalizedResult]:
        results: list[NormalizedResult] = []
        for item in data.get("results", data.get("prompts", [])):
            grading = item.get("gradingResult") or item.get("grading") or {}
            passed = bool(grading.get("pass", item.get("pass", True)))
            if passed:
                continue
            test = item.get("test") or item.get("vars") or {}
            category = item.get("category") or test.get("category") or "llm_redteam"
            title = item.get("description") or test.get("description") or item.get("prompt") or "Promptfoo finding"
            testcase_id = item.get("testcase_id") or test.get("testcase_id") or item.get("id")
            score = safe_float(grading.get("score"))
            results.append(
                NormalizedResult(
                    run_id=run_id,
                    target_id=target_id,
                    source=ToolSource(self.tool, version),
                    category=str(category),
                    title=str(title),
                    testcase_id=None if testcase_id is None else str(testcase_id),
                    raw_artifact_ref=raw_artifact_ref,
                    detector_score=score,
                    framework_tags=_framework_tags(item, test),
                    metadata={"raw": item, "reason": grading.get("reason")},
                )
            )
        return results


def _framework_tags(*items: dict[str, Any]) -> dict[str, list[str]]:
    tags: dict[str, list[str]] = {}
    for item in items:
        frameworks = item.get("frameworks") or item.get("framework_tags") or {}
        if isinstance(frameworks, dict):
            for key, value in frameworks.items():
                tags[str(key)] = [str(entry) for entry in value]
    return tags

