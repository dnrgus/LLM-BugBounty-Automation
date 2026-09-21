from __future__ import annotations

import json
from pathlib import Path

from core.models import Run
from findings.dedup import FindingCluster


def write_cluster_report(directory: Path, run: Run, clusters: list[FindingCluster]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{run.id}_root_cause_clusters.json"
    payload = {
        "run_id": run.id,
        "cluster_count": len(clusters),
        "finding_count": sum(cluster.count for cluster in clusters),
        "clusters": [cluster.to_dict() for cluster in clusters],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path
