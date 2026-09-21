from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from attack_surface.merge import merge_items
from attack_surface.models import AttackSurfaceItem
from live.discovery import DiscoveryResult
from source.analyzers import analyze_files
from source.ingestion import ingest_source
from source.routes import extract_routes


@dataclass
class CorrelationResult:
    source_root: str
    live_base_url: str
    items: list[AttackSurfaceItem] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        corroborated = [item for item in self.items if item.source_type == "merged"]
        return {
            "source_root": self.source_root,
            "live_base_url": self.live_base_url,
            "attack_surface": {
                "total": len(self.items),
                "corroborated_by_both": len(corroborated),
                "items": [item.to_dict() for item in self.items],
            },
        }


def correlate_source_and_live(
    source_root: Path | str, live_result: DiscoveryResult, max_files: int = 2000
) -> CorrelationResult:
    """U8 HYBRID MODE (design doc section 10, "root cause/live evidence
    merge"): joins SOURCE static analysis (U3) with LIVE discovery (U4)
    through the common AttackSurfaceItem model and its existing merge
    rules (U2's attack_surface.merge.merge_items()).

    A SOURCE-detected route that is ALSO seen LIVE is the "root cause +
    live evidence" story this phase exists for: a real, network-reachable
    surface, not just a theoretical one found by pattern-matching source
    code -- merge_items() already raises confidence and tags the result
    source_type="merged" for exactly this case, so this function's whole
    job is wiring SOURCE ingestion and a LIVE discovery result into that
    existing join, not reimplementing correlation logic.

    Neither SOURCE mode nor LIVE mode itself is re-run or modified here
    -- the caller supplies an already-completed DiscoveryResult (from
    live.discovery.discover_target) so this module never has to reissue
    network requests or re-derive a Scope/Policy decision on its own.
    """
    ingestion = ingest_source(source_root, max_files=max_files)
    source_items = extract_routes(ingestion.files) + analyze_files(ingestion.files)
    merged = merge_items(source_items + live_result.items)
    return CorrelationResult(source_root=str(ingestion.root), live_base_url=live_result.base_url, items=merged)
