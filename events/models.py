from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class EventType(str, Enum):
    START = "start"
    TOKEN = "token"
    RETRIEVAL = "retrieval"
    TOOL_CALL = "tool_call"
    FINAL = "final"
    ERROR = "error"


@dataclass(frozen=True)
class Event:
    type: EventType
    sequence: int
    data: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {"type": self.type.value, "sequence": self.sequence, "data": self.data}
