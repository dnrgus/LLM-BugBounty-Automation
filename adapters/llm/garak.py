from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adapters.base import NormalizedResult, ToolSource, safe_float


class GarakAdapter:
    tool = "garak"

    def parse_file(
        self,
        path: Path | str,
        run_id: str,
        target_id: str,
        version: str | None = None,
    ) -> list[NormalizedResult]:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        records = [json.loads(line) for line in lines if line.strip()]
        return self.parse(records, run_id=run_id, target_id=target_id, version=version, raw_artifact_ref=str(path))

    def parse(
        self,
        records: list[dict[str, Any]],
        run_id: str,
        target_id: str,
        version: str | None = None,
        raw_artifact_ref: str | None = None,
    ) -> list[NormalizedResult]:
        results: list[NormalizedResult] = []
        for item in records:
            if item.get("entry_type") not in {None, "eval", "finding"}:
                continue
            passed = item.get("passed")
            detector_score = safe_float(item.get("detector_score", item.get("score")))
            vulnerable = item.get("vulnerable")
            is_finding = vulnerable is True or passed is False or (detector_score is not None and detector_score > 0)
            if not is_finding:
                continue
            probe = item.get("probe") or item.get("probe_classname") or "garak_probe"
            detector = item.get("detector") or item.get("detector_classname") or "garak_detector"
            results.append(
                NormalizedResult(
                    run_id=run_id,
                    target_id=target_id,
                    source=ToolSource(self.tool, version),
                    category=str(item.get("category") or probe),
                    title=f"{probe} / {detector}",
                    testcase_id=None if item.get("testcase_id") is None else str(item["testcase_id"]),
                    raw_artifact_ref=raw_artifact_ref,
                    detector_score=detector_score,
                    framework_tags=_framework_tags(item),
                    metadata={"raw": item},
                )
            )
        return results


def _framework_tags(item: dict[str, Any]) -> dict[str, list[str]]:
    frameworks = item.get("frameworks") or item.get("framework_tags") or {}
    if not isinstance(frameworks, dict):
        return {}
    return {str(key): [str(entry) for entry in value] for key, value in frameworks.items()}

