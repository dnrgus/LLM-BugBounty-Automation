from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from core.models import CapabilityProfile, TraceEvent


@dataclass(frozen=True)
class TargetMetadata:
    id: str
    kind: str
    provider: str
    name: str
    version: str
    base_url: str
    extra: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class TargetResponse:
    prompt: str
    text: str
    metadata: dict[str, object] = field(default_factory=dict)
    trace_events: list[TraceEvent] = field(default_factory=list)


class TargetAdapter(Protocol):
    async def healthcheck(self) -> bool: ...

    async def metadata(self) -> TargetMetadata: ...

    async def capabilities(self) -> CapabilityProfile: ...

    async def send(self, prompt: str, session: str | None = None) -> TargetResponse: ...

    async def reset_session(self, session: str | None = None) -> None: ...

    async def trace(self, session: str | None = None) -> list[TraceEvent]: ...
