from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adapters.base import NormalizedResult, ToolSource

_SEVERITY_SCORE = {"info": 0.1, "low": 0.3, "medium": 0.5, "high": 0.8, "critical": 1.0}


class NucleiAdapter:
    tool = "nuclei"

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
            info = item.get("info") or {}
            severity = str(info.get("severity", "info")).lower()
            tags = info.get("tags") or []
            category = tags[0] if tags else item.get("template-id", "nuclei_finding")
            results.append(
                NormalizedResult(
                    run_id=run_id,
                    target_id=target_id,
                    source=ToolSource(self.tool, version),
                    category=str(category),
                    title=str(info.get("name") or item.get("template-id") or "Nuclei finding"),
                    endpoint=item.get("matched-at") or item.get("host"),
                    raw_artifact_ref=raw_artifact_ref,
                    detector_score=_SEVERITY_SCORE.get(severity, 0.0),
                    framework_tags=_framework_tags(item),
                    metadata={
                        "template_id": item.get("template-id"),
                        "tags": tags,
                        "severity": severity,
                        "raw": item,
                    },
                )
            )
        return results


def _framework_tags(item: dict[str, Any]) -> dict[str, list[str]]:
    frameworks = item.get("frameworks") or item.get("framework_tags") or {}
    if not isinstance(frameworks, dict):
        return {}
    return {str(key): [str(entry) for entry in value] for key, value in frameworks.items()}
