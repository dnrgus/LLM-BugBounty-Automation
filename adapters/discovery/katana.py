from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.models import Endpoint


class KatanaAdapter:
    tool = "katana"

    def parse_file(self, path: Path | str, run_id: str, target_id: str) -> list[Endpoint]:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        records = [json.loads(line) for line in lines if line.strip()]
        return self.parse(records, run_id=run_id, target_id=target_id)

    def parse(self, records: list[dict[str, Any]], run_id: str, target_id: str) -> list[Endpoint]:
        endpoints: list[Endpoint] = []
        for record in records:
            request = record.get("request") or {}
            url = request.get("endpoint")
            if not url:
                continue
            response = record.get("response") or {}
            endpoints.append(
                Endpoint(
                    run_id=run_id,
                    target_id=target_id,
                    url=str(url),
                    method=str(request.get("method", "GET")),
                    source=self.tool,
                    status_code=response.get("status_code"),
                    metadata={"source_page": request.get("source")},
                )
            )
        return endpoints
