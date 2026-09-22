from __future__ import annotations

from dataclasses import dataclass

from attack_surface.models import AttackSurfaceItem
from core.models import Finding
from correlation.resolver import EntityMatch
from validation.planner import ValidationPlan


@dataclass(frozen=True)
class CorrelatedFinding:
    """P3.3-3 (roadmap v3.3.0 Static -> Dynamic Validation): links a
    dynamically-produced Finding back to the static candidate and
    EntityMatch that justified testing it, so a report can distinguish
    "static-only" candidates from ones with real origin=[static,dynamic]
    evidence -- confirmed/rejected/unstable all carry this provenance
    equally; only whether a Finding exists at all differs.
    """

    finding: Finding
    static_candidate: AttackSurfaceItem
    match: EntityMatch
    plan: ValidationPlan

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding.id,
            "finding_status": self.finding.status.value,
            "static_candidate_id": self.static_candidate.id,
            "static_candidate_asset_type": self.static_candidate.asset_type,
            "match_basis": self.match.basis,
            "match_confidence": self.match.confidence,
            "origin": ["static", "dynamic"],
        }
