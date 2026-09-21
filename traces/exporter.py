from __future__ import annotations

import json
from pathlib import Path

from core.models import TraceEvent


def export_trace(path: Path, events: list[TraceEvent]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps([event.__dict__ for event in events], indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return path

