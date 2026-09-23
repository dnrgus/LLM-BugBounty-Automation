from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from attack_surface.models import AttackSurfaceItem


@dataclass(frozen=True)
class GroundTruthFinding:
    """P4.4-A (roadmap v4.4.0 Accuracy & Benchmark): one KNOWN
    vulnerability/signal a benchmark fixture is documented to contain --
    the thing SOURCE MODE (`audit <path>`) is expected to actually find.

    Deliberately matches on the same static, deterministic evidence
    SOURCE MODE already produces (asset_type + file, optionally
    sink_type/secret_type/line) rather than anything dynamic -- ground
    truth for a fixture app is a property of its source code, not of
    whether a particular run happened to reach a live target.
    """

    id: str
    asset_type: str
    file: str
    line: int | None = None
    sink_type: str | None = None
    secret_type: str | None = None
    severity: str = "medium"
    description: str = ""

    def matches(self, item: AttackSurfaceItem) -> bool:
        if item.asset_type != self.asset_type:
            return False
        if str(item.metadata.get("file", "")) != self.file:
            return False
        if self.line is not None and int(item.metadata.get("line", -1) or -1) != self.line:
            return False
        if self.sink_type is not None and item.metadata.get("sink_type") != self.sink_type:
            return False
        if self.secret_type is not None and item.metadata.get("secret_type") != self.secret_type:
            return False
        return True

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id, "asset_type": self.asset_type, "file": self.file, "line": self.line,
            "sink_type": self.sink_type, "secret_type": self.secret_type, "severity": self.severity,
            "description": self.description,
        }


@dataclass(frozen=True)
class GroundTruthCorpusEntry:
    fixture_path: str
    findings: list[GroundTruthFinding] = field(default_factory=list)


def load_ground_truth(path: Path | str) -> GroundTruthCorpusEntry:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    findings = [GroundTruthFinding(**item) for item in data.get("findings", [])]
    return GroundTruthCorpusEntry(fixture_path=str(data.get("fixture_path", "")), findings=findings)


def load_ground_truth_corpus(corpus_dir: Path | str) -> list[GroundTruthCorpusEntry]:
    """Loads every `*.ground_truth.yaml` file directly under `corpus_dir`
    (not recursive -- one file per benchmark fixture, kept flat and
    easy to list)."""
    root = Path(corpus_dir)
    if not root.is_dir():
        return []
    return [load_ground_truth(path) for path in sorted(root.glob("*.ground_truth.yaml"))]
