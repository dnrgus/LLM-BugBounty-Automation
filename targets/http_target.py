from __future__ import annotations

import os
from dataclasses import dataclass, field

import httpx

from core.models import CapabilityProfile, TraceEvent
from targets.base import TargetMetadata, TargetResponse


@dataclass(frozen=True)
class HTTPTargetConfig:
    id: str
    kind: str
    provider: str
    name: str
    version: str
    base_url: str
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 30.0
    capabilities: dict[str, bool] = field(default_factory=lambda: {"chat": True})
    transport: httpx.BaseTransport | None = field(default=None, repr=False)


class OpenAICompatibleTarget:
    """Target Adapter for OpenAI-compatible chat completion APIs.

    Works against OpenAI, Azure OpenAI, and most self-hosted gateways
    (vLLM, LiteLLM, Ollama's OpenAI shim, etc.) since they all implement
    POST {base_url}/chat/completions. Maintains per-session message
    history so multi-turn testcases are threaded correctly.

    Real network calls go through Executor.execute(), which already
    validates the URL against Scope + Program Policy before send() is
    ever called, and retries/backoff on failure -- this adapter does not
    need its own retry logic.
    """

    def __init__(self, config: HTTPTargetConfig):
        self.config = config
        self._sessions: dict[str, list[dict[str, str]]] = {}
        self._trace: dict[str, list[TraceEvent]] = {}

    async def healthcheck(self) -> bool:
        try:
            async with self._client() as client:
                response = await client.get(f"{self._base}/models")
            return response.status_code < 500
        except httpx.HTTPError:
            return False

    async def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            id=self.config.id,
            kind=self.config.kind,
            provider=self.config.provider,
            name=self.config.name,
            version=self.config.version,
            base_url=self.config.base_url,
        )

    async def capabilities(self) -> CapabilityProfile:
        return CapabilityProfile(**self.config.capabilities)

    async def send(self, prompt: str, session: str | None = None) -> TargetResponse:
        session_id = session or "default"
        history = self._sessions.setdefault(session_id, [])
        history.append({"role": "user", "content": prompt})

        async with self._client() as client:
            response = await client.post(
                f"{self._base}/chat/completions",
                json={"model": self.config.name, "messages": history},
            )
        response.raise_for_status()
        data = response.json()
        text = data["choices"][0]["message"]["content"]
        history.append({"role": "assistant", "content": text})

        events = self._trace.setdefault(session_id, [])
        event = TraceEvent(
            trace_id=session_id,
            sequence=len(events) + 1,
            event_type="llm_call",
            metadata={"status_code": response.status_code, "model": self.config.name},
        )
        events.append(event)

        return TargetResponse(
            prompt=prompt,
            text=text,
            metadata={"session": session_id, "status_code": response.status_code, "usage": data.get("usage")},
            trace_events=[event],
        )

    async def reset_session(self, session: str | None = None) -> None:
        if session is None:
            self._sessions.clear()
            self._trace.clear()
            return
        self._sessions.pop(session, None)
        self._trace.pop(session, None)

    async def trace(self, session: str | None = None) -> list[TraceEvent]:
        if session is None:
            return [event for events in self._trace.values() for event in events]
        return list(self._trace.get(session, []))

    @property
    def _base(self) -> str:
        return self.config.base_url.rstrip("/")

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers=self.config.headers,
            timeout=self.config.timeout_seconds,
            transport=self.config.transport,
        )


def openai_target_from_env(
    base_url: str | None = None,
    model: str | None = None,
    api_key_env: str = "OPENAI_API_KEY",
) -> OpenAICompatibleTarget:
    """Builds an OpenAICompatibleTarget from environment variables.

    Never hardcode API keys: set OPENAI_API_KEY (or pass a different
    api_key_env for an alternate provider's key) in your shell or .env,
    which is gitignored.
    """
    api_key = os.environ.get(api_key_env)
    if not api_key:
        raise RuntimeError(f"{api_key_env} is not set; export it (see .env.example) before using this target")
    resolved_base_url = base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    resolved_model = model or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    config = HTTPTargetConfig(
        id="openai-compatible",
        kind="llm",
        provider="openai-compatible",
        name=resolved_model,
        version=resolved_model,
        base_url=resolved_base_url,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    )
    return OpenAICompatibleTarget(config)
