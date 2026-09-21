from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.models import TraceEvent


def _event_to_dict(event: TraceEvent | Any) -> dict[str, object]:
    if isinstance(event, TraceEvent):
        return event.__dict__
    if hasattr(event, "keys"):
        return {key: event[key] for key in event.keys()}
    raise TypeError(f"unsupported trace event type: {type(event)!r}")


def export_trace(path: Path, events: list[TraceEvent | Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps([_event_to_dict(event) for event in events], indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return path
