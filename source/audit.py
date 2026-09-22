from __future__ import annotations

from pathlib import Path

from source.analyzers import analyze_files
from source.ingestion import ingest_source
from source.routes import extract_routes


def audit_source(root: Path | str, max_files: int = 2000) -> dict[str, object]:
    """SOURCE MODE entrypoint (design doc section 8): ingest a source tree,
    extract routes, and run the input/sink/secret/LLM analyzers, returning
    a flat AttackSurfaceItem list plus a summary. Static findings only --
    exploitability confirmation is LIVE verification's job (HYBRID MODE,
    U8), not this module's.
    """
    ingestion = ingest_source(root, max_files=max_files)
    routes = extract_routes(ingestion.files)
    items = routes + analyze_files(ingestion.files, routes)

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
    }
