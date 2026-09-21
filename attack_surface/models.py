from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from core.models import new_id

SourceType = Literal["live", "source", "merged"]


@dataclass(frozen=True)
class AttackSurfaceItem:
    """Common intermediate model (design doc section 5) that LIVE Discovery
    and SOURCE static analysis results join through, so neither path has to
    depend on the other directly.
    """

    source_type: SourceType
    asset_type: str  # endpoint, parameter, function, secret, llm, rag, agent...
    location: str
    metadata: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    evidence_refs: list[str] = field(default_factory=list)
    correlation_keys: list[str] = field(default_factory=list)
    provenance: list[dict[str, Any]] = field(default_factory=list)
    id: str = field(default_factory=lambda: new_id("AS"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_type": self.source_type,
            "asset_type": self.asset_type,
            "location": self.location,
            "metadata": self.metadata,
            "confidence": self.confidence,
            "evidence_refs": self.evidence_refs,
            "correlation_keys": self.correlation_keys,
            "provenance": self.provenance,
        }
