from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adapters.base import NormalizedResult, ToolSource


class PyRITAdapter:
    tool = "pyrit"

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
        attempts = data.get("attempts") or data.get("results") or []
        results: list[NormalizedResult] = []
        for attempt in attempts:
            score = attempt.get("score", attempt.get("objective_score"))
            success = bool(attempt.get("success", attempt.get("objective_achieved", False)))
            if not success and not (score is not None and float(score) > 0):
                continue
            objective = attempt.get("objective") or data.get("objective") or "PyRIT adaptive objective"
            category = attempt.get("category") or data.get("category") or "adaptive_redteam"
            turns = attempt.get("conversation") or attempt.get("turns") or []
            results.append(
                NormalizedResult(
                    run_id=run_id,
                    target_id=target_id,
                    source=ToolSource(self.tool, version),
                    category=str(category),
                    title=str(objective),
                    testcase_id=None if attempt.get("testcase_id") is None else str(attempt["testcase_id"]),
                    trace_ref=attempt.get("trace_ref"),
                    raw_artifact_ref=raw_artifact_ref,
                    detector_score=None if score is None else float(score),
                    framework_tags=_framework_tags(attempt, data),
                    metadata={
                        "turn_count": len(turns),
                        "conversation": turns,
                        "strategy": attempt.get("strategy"),
                        "raw": attempt,
                    },
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

