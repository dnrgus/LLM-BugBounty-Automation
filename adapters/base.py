from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolSource:
    tool: str
    version: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class NormalizedResult:
    run_id: str
    target_id: str
    source: ToolSource
    category: str
    title: str
    endpoint: str | None = None
    testcase_id: str | None = None
    trace_ref: str | None = None
    raw_artifact_ref: str | None = None
    detector_score: float | None = None
    framework_tags: dict[str, list[str]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["source"] = self.source.to_dict()
        return data

