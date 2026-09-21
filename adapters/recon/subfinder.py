from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.models import Asset


class SubfinderAdapter:
    tool = "subfinder"

    def parse_file(self, path: Path | str, run_id: str, target_id: str) -> list[Asset]:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        records = [json.loads(line) for line in lines if line.strip()]
        return self.parse(records, run_id=run_id, target_id=target_id)

    def parse(self, records: list[dict[str, Any]], run_id: str, target_id: str) -> list[Asset]:
        assets: list[Asset] = []
        seen: set[str] = set()
        for record in records:
            host = record.get("host")
            if not host or host in seen:
                continue
            seen.add(host)
            assets.append(Asset(run_id=run_id, target_id=target_id, domain=str(host), source=self.tool))
        return assets
