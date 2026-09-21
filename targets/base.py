from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from core.models import CapabilityProfile


@dataclass(frozen=True)
class TargetResponse:
    prompt: str
    text: str
    metadata: dict[str, object]


class TargetAdapter(Protocol):
    async def healthcheck(self) -> bool: ...

    async def metadata(self) -> dict[str, object]: ...

    async def capabilities(self) -> CapabilityProfile: ...

    async def send(self, prompt: str, session: str | None = None) -> TargetResponse: ...

    async def reset_session(self) -> None: ...

