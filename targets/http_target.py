from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

import httpx

from core.models import CapabilityProfile, TraceEvent
from targets.base import TargetMetadata, TargetResponse
from targets.errors import (
    TargetAuthenticationError,
    TargetConnectionError,
    TargetParseError,
    TargetRateLimitError,
    TargetServerError,
)


def _raise_for_transport_error(exc: httpx.HTTPError) -> None:
    if isinstance(exc, httpx.TimeoutException):
        raise TargetConnectionError(f"request timed out: {exc}") from exc
    if isinstance(exc, httpx.ConnectError):
        raise TargetConnectionError(f"connection failed: {exc}") from exc
    raise TargetConnectionError(str(exc)) from exc


def _raise_for_status(response: httpx.Response) -> None:
    if response.status_code in (401, 403):
        raise TargetAuthenticationError(f"authentication failed (status {response.status_code})")
    if response.status_code == 429:
        raise TargetRateLimitError("rate limited (status 429)")
    if response.status_code >= 500:
        raise TargetServerError(f"target server error (status {response.status_code})")
    response.raise_for_status()


def extract_json_path(data: Any, path: str) -> Any:
    """Resolves a dot-separated path (e.g. "choices.0.message.content" or
    "reply.text") into a parsed JSON response. Array indices are plain
    integers in the path, e.g. "choices.0.text"."""
    current = data
    for part in path.split("."):
        try:
            if isinstance(current, list):
                current = current[int(part)]
            elif isinstance(current, dict):
                current = current[part]
            else:
                raise TargetParseError(f"cannot resolve '{part}' in response path '{path}': not a dict/list")
        except (KeyError, IndexError, ValueError) as exc:
            raise TargetParseError(f"failed to resolve '{part}' in response path '{path}': {exc}") from exc
    return current


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
        # base_url reports the actual endpoint send() hits (not the bare API
        # root) so Executor's pre-request Scope/Policy check -- which
        # validates this value -- lines up with what config/scope.yaml's
        # url_patterns are written against.
        return TargetMetadata(
            id=self.config.id,
            kind=self.config.kind,
            provider=self.config.provider,
            name=self.config.name,
            version=self.config.version,
            base_url=f"{self._base}/chat/completions",
        )

    async def capabilities(self) -> CapabilityProfile:
        return CapabilityProfile(**self.config.capabilities)

    async def send(self, prompt: str, session: str | None = None) -> TargetResponse:
        session_id = session or "default"
        history = self._sessions.setdefault(session_id, [])
        history.append({"role": "user", "content": prompt})

        try:
            async with self._client() as client:
                response = await client.post(
                    f"{self._base}/chat/completions",
                    json={"model": self.config.name, "messages": history},
                )
        except httpx.HTTPError as exc:
            _raise_for_transport_error(exc)

        _raise_for_status(response)
        data = response.json()
        text = extract_json_path(data, "choices.0.message.content")
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


def _substitute(template: Any, values: dict[str, str]) -> Any:
    if isinstance(template, str):
        result = template
        for key, val in values.items():
            result = result.replace("{{" + key + "}}", val)
        return result
    if isinstance(template, dict):
        return {key: _substitute(val, values) for key, val in template.items()}
    if isinstance(template, list):
        return [_substitute(item, values) for item in template]
    return template


@dataclass(frozen=True)
class CustomHTTPConfig:
    """Config for an arbitrary REST API target with its own JSON schema.

    request_body_template is rendered with {{PROMPT}}, {{SESSION}}, and
    {{HISTORY_JSON}} (a JSON-encoded [{"role","content"}, ...] list of the
    session's prior turns) substituted into any string value, at any
    nesting depth -- so it can match whatever shape the target's API
    expects, e.g. {"query": "{{PROMPT}}", "conversation_id": "{{SESSION}}"}.
    """

    id: str
    kind: str
    provider: str
    name: str
    version: str
    base_url: str
    request_path: str = ""
    method: str = "POST"
    request_body_template: dict[str, Any] = field(default_factory=lambda: {"message": "{{PROMPT}}"})
    response_text_path: str = "response"
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 30.0
    capabilities: dict[str, bool] = field(default_factory=lambda: {"chat": True})
    transport: httpx.BaseTransport | None = field(default=None, repr=False)


class CustomHTTPAdapter:
    """Target Adapter for a REST API with a custom, configurable JSON schema.

    Unlike OpenAICompatibleTarget, the request/response shape is entirely
    driven by CustomHTTPConfig rather than assumed -- this is the adapter
    for a bug bounty target's own bespoke chat/completion endpoint.
    """

    def __init__(self, config: CustomHTTPConfig):
        self.config = config
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
        # See OpenAICompatibleTarget.metadata() -- same reasoning: report the
        # actual endpoint, not the bare base_url.
        return TargetMetadata(
            id=self.config.id,
            kind=self.config.kind,
            provider=self.config.provider,
            name=self.config.name,
            version=self.config.version,
            base_url=f"{self._base}{self.config.request_path}",
        )

    async def capabilities(self) -> CapabilityProfile:
        return CapabilityProfile(**self.config.capabilities)

    async def send(self, prompt: str, session: str | None = None) -> TargetResponse:
        session_id = session or "default"
        history = self._history.setdefault(session_id, [])

        values = {
            "PROMPT": prompt,
            "SESSION": session_id,
            "HISTORY_JSON": json.dumps(history, ensure_ascii=False),
        }
        body = _substitute(self.config.request_body_template, values)
        url = f"{self._base}{self.config.request_path}"

        try:
            async with self._client() as client:
                response = await client.request(self.config.method, url, json=body)
        except httpx.HTTPError as exc:
            _raise_for_transport_error(exc)

        _raise_for_status(response)
        data = response.json()
        text = str(extract_json_path(data, self.config.response_text_path))

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
        if session is None:
            self._history.clear()
            self._trace.clear()
            return
        self._history.pop(session, None)
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
