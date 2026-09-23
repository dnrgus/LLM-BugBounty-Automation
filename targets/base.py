from __future__ import annotations

from dataclasses import dataclass, field
from typing import AsyncIterator, Protocol

from core.models import CapabilityProfile, TraceEvent
from events.models import Event


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


class StreamingTargetAdapter(TargetAdapter, Protocol):
    """P4.3-A (roadmap v4.3.0 Runtime Coverage Expansion): an *optional*
    extension of TargetAdapter -- `events()` is additive, alongside the
    existing `send()`, never replacing it. Every existing adapter and
    every existing pipeline path (Executor, Reproducer, Judge) keeps
    calling `send()` for one aggregated TargetResponse, completely
    unchanged; a caller that specifically wants incremental events (a
    streaming-aware Judge check, a CLI that prints tokens as they
    arrive) can check `supports_streaming()` first and use `events()`
    instead.
    """

    def events(self, prompt: str, session: str | None = None) -> AsyncIterator[Event]: ...


def supports_streaming(target: TargetAdapter) -> bool:
    """True if `target` implements the optional events() extension --
    structural check (duck typing), since StreamingTargetAdapter is a
    Protocol and isinstance() against it would require @runtime_checkable
    plus still only checking method *names*, not their async-generator
    nature; hasattr is exactly as precise here and doesn't need that
    decorator on a Protocol most adapters never implement.
    """
    return hasattr(target, "events")
