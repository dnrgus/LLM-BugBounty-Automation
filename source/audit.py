from __future__ import annotations

from pathlib import Path

from attack_surface.models import AttackSurfaceItem
from source.analyzers import analyze_files
from source.endpoints import build_endpoint_inventory
from source.ingestion import SourceIngestionResult, ingest_source
from source.routes import extract_routes


def collect_source_items(
    root: Path | str, max_files: int = 2000, stats_out: dict[str, object] | None = None
) -> tuple[SourceIngestionResult, list[AttackSurfaceItem]]:
    """The actual SOURCE MODE analysis, returning raw AttackSurfaceItem
    objects rather than audit_source()'s serialized dict -- for a caller
    (P3.3-4's HYBRID orchestrator) that needs to feed them into
    correlation/resolver.py or validation/planner.py rather than just
    display them.
    """
    ingestion = ingest_source(root, max_files=max_files)
    routes = extract_routes(ingestion.files)
    items = routes + analyze_files(ingestion.files, routes, stats_out=stats_out)
    return ingestion, items


def audit_source(root: Path | str, max_files: int = 2000) -> dict[str, object]:
    """SOURCE MODE entrypoint (design doc section 8): ingest a source tree,
    extract routes, and run the input/sink/secret/LLM analyzers, returning
    a flat AttackSurfaceItem list plus a summary. Static findings only --
    exploitability confirmation is LIVE verification's job (HYBRID MODE,
    U8/P3.3), not this module's.
    """
    interprocedural_stats: dict[str, object] = {}
    ingestion, items = collect_source_items(root, max_files=max_files, stats_out=interprocedural_stats)

    by_asset_type: dict[str, int] = {}
    for item in items:
        by_asset_type[item.asset_type] = by_asset_type.get(item.asset_type, 0) + 1

    return {
        "root": str(ingestion.root),
        "primary_language": ingestion.primary_language,
        "language_counts": ingestion.language_counts,
        "frameworks": ingestion.frameworks,
        "files_scanned": len(ingestion.files),
        "attack_surface": {
            "total": len(items),
            "by_asset_type": by_asset_type,
            "items": [item.to_dict() for item in items],
        },
        # P4.5 WP-01: one entry per (route, concrete method) -- state-
        # changing methods included, with inferred request shape.
        "endpoint_inventory": [spec.to_dict() for spec in build_endpoint_inventory(items)],
        # P4.6 WP-04: depth/node/time caps hit, if any.
        "interprocedural": interprocedural_stats,
    }
