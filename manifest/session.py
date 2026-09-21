from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SessionPolicy:
    """Whether prior turns get replayed into subsequent requests
    (stateful, the default -- matches CustomHTTPAdapter/
    OpenAICompatibleTarget's existing client-side history) or every send()
    is independent (stateless -- for a target that carries its own state
    server-side, e.g. via a cookie the Transport/Auth layer already
    attaches, where replaying history client-side would duplicate turns).
    """

    stateful: bool = True


def build_session_policy(config: dict[str, Any]) -> SessionPolicy:
    return SessionPolicy(stateful=bool(config.get("stateful", True)))
