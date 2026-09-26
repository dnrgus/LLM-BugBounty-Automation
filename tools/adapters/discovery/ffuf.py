from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.models import Endpoint


class FfufAdapter:
    tool = "ffuf"

    def parse_file(self, path: Path | str, run_id: str, target_id: str) -> list[Endpoint]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.parse(data, run_id=run_id, target_id=target_id)

    def parse(self, data: dict[str, Any], run_id: str, target_id: str) -> list[Endpoint]:
        endpoints: list[Endpoint] = []
        for result in data.get("results", []):
            url = result.get("url")
            if not url:
                continue
            endpoints.append(
                Endpoint(
                    run_id=run_id,
                    target_id=target_id,
                    url=str(url),
                    method="GET",
                    source=self.tool,
                    status_code=result.get("status"),
                    metadata={
                        "length": result.get("length"),
                        "words": result.get("words"),
                        "input": result.get("input"),
                    },
                )
            )
        return endpoints
