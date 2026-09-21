from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from core.models import CapabilityProfile, TraceEvent
from manifest.auth import AuthProvider
from manifest.interaction import Interaction
from manifest.session import SessionPolicy
from targets.base import TargetMetadata, TargetResponse
from targets.http_target import _raise_for_status, _raise_for_transport_error


@dataclass(frozen=True)
class ManifestTargetConfig:
    id: str
    name: str
    version: str
    base_url: str
    auth: AuthProvider
    interaction: Interaction
    session_policy: SessionPolicy
    capabilities: dict[str, bool] = field(default_factory=lambda: {"chat": True})
    timeout_seconds: float = 30.0
    extra_headers: dict[str, str] = field(default_factory=dict)
    transport: httpx.BaseTransport | None = field(default=None, repr=False)


class CompatibilityAdapter:
    """U10 Universal Manifest (design doc section 12): a TargetAdapter
    assembled from independently-configurable Auth / Transport /
    Interaction / Session pieces, instead of one hardcoded class per
    target shape.

    This wraps the same low-level HTTP request/response handling
    (extract_json_path, status/transport error mapping) that
    OpenAICompatibleTarget and CustomHTTPAdapter already use -- it is a
    third, additive way to build a TargetAdapter; targets/config.py's
    existing "openai_compatible"/"custom_http" kinds and their
    target.yaml schema are unchanged.

    Auth headers are resolved once at construction (matching
    targets/config.py's existing _resolve_auth_header, which fails fast
    at load time rather than on first request) and reused for every
    send().
    """

    def __init__(self, config: ManifestTargetConfig):
        self.config = config
        self._auth_headers = config.auth.headers()
        self._history: dict[str, list[dict[str, str]]] = {}
        self._trace: dict[str, list[TraceEvent]] = {}

    async def healthcheck(self) -> bool:
        try:
            async with self._client() as client:
                response = await client.get(self._base or "/")
            return response.status_code < 500
        except httpx.HTTPError:
            return False

    async def metadata(self) -> TargetMetadata:
        # See targets/http_target.py's adapters -- report the actual
        # endpoint the interaction sends to, not the bare base_url, so
        # Scope/Policy checks validate what's really requested.
        return TargetMetadata(
            id=self.config.id,
            kind="llm",
            provider="universal-manifest",
            name=self.config.name,
            version=self.config.version,
            base_url=f"{self._base}{self.config.interaction.request_path}",
        )

    async def capabilities(self) -> CapabilityProfile:
        return CapabilityProfile(**self.config.capabilities)

    async def send(self, prompt: str, session: str | None = None) -> TargetResponse:
        session_id = session or "default"
        history = self._history.setdefault(session_id, []) if self.config.session_policy.stateful else []
        body = self.config.interaction.build_body(prompt, session_id, history)
        url = f"{self._base}{self.config.interaction.request_path}"
        headers = {"Content-Type": "application/json", **self.config.extra_headers, **self._auth_headers}

        try:
            async with self._client() as client:
                response = await client.request(self.config.interaction.method, url, json=body, headers=headers)
        except httpx.HTTPError as exc:
            _raise_for_transport_error(exc)

        _raise_for_status(response)
        text = self.config.interaction.parse_response(response.json())

        if self.config.session_policy.stateful:
            history.append({"role": "user", "content": prompt})
            history.append({"role": "assistant", "content": text})

        events = self._trace.setdefault(session_id, [])
        event = TraceEvent(
            trace_id=session_id,
            sequence=len(events) + 1,
            event_type="llm_call",
            metadata={"status_code": response.status_code, "url": url},
        )
        events.append(event)

        return TargetResponse(
            prompt=prompt,
            text=text,
            metadata={"session": session_id, "status_code": response.status_code},
            trace_events=[event],
        )

    async def reset_session(self, session: str | None = None) -> None:
        session_id = session or "default"
        self._history.pop(session_id, None)
        self._trace.pop(session_id, None)

    async def trace(self, session: str | None = None) -> list[TraceEvent]:
        if session is None:
            return [event for events in self._trace.values() for event in events]
        return list(self._trace.get(session, []))

    @property
    def _base(self) -> str:
        return self.config.base_url.rstrip("/")

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=self.config.timeout_seconds, transport=self.config.transport)
