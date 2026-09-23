from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

import httpx

from core.models import CapabilityProfile, TraceEvent
from events.models import Event, EventType
from targets.base import TargetMetadata, TargetResponse
from targets.errors import TargetConnectionError, TargetParseError


@dataclass(frozen=True)
class SSETargetConfig:
    """P4.3-B (roadmap v4.3.0 Runtime Coverage Expansion): the HTTP
    Server-Sent-Events / chunked-streaming counterpart to
    events/websocket_target.py's generic WS transport. Frame shape is
    configurable the same way (type_field/text_field/*_types), since
    different SSE-based LLM/agent APIs disagree on it.
    """

    id: str
    name: str
    version: str
    url: str
    method: str = "POST"
    headers: dict[str, str] = field(default_factory=dict)
    request_body_template: dict[str, Any] = field(default_factory=lambda: {"message": "{{PROMPT}}"})
    type_field: str = "type"
    text_field: str = "content"
    final_types: tuple[str, ...] = ("final", "done", "end")
    error_types: tuple[str, ...] = ("error",)
    capabilities: dict[str, bool] = field(default_factory=lambda: {"chat": True})
    timeout_seconds: float = 30.0
    transport: httpx.AsyncBaseTransport | None = None  # injectable for tests, mirrors validation/*_validator.py's own pattern


class SSETargetAdapter:
    """Connects to an arbitrary SSE (`text/event-stream`) or chunked
    HTTP streaming target, sends one JSON prompt body, and interprets
    the resulting `data: {...}` frame stream as the same formal Event
    sequence (START/TOKEN/RETRIEVAL/TOOL_CALL/FINAL/ERROR)
    events/websocket_target.py already uses.

    Implements both the existing TargetAdapter protocol (`send()`
    returns one aggregated TargetResponse, so this slots into the
    existing Executor/pipeline completely unchanged) and the new
    StreamingTargetAdapter protocol's `events()` (P4.3-A) -- `send()`
    is itself built on top of `events()`, so there is exactly one place
    that actually interprets a frame.
    """

    def __init__(self, config: SSETargetConfig):
        self.config = config
        self._trace: dict[str, list[TraceEvent]] = {}

    async def healthcheck(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds, transport=self.config.transport) as client:
                response = await client.request(self.config.method, self.config.url, json={"health_check": True})
                return response.status_code < 500
        except Exception:
            return False

    async def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            id=self.config.id,
            kind="llm",
            provider="sse-generic",
            name=self.config.name,
            version=self.config.version,
            base_url=self.config.url,
        )

    async def capabilities(self) -> CapabilityProfile:
        return CapabilityProfile(**self.config.capabilities)

    async def events(self, prompt: str, session: str | None = None) -> AsyncIterator[Event]:
        session_id = session or "default"
        body = _render_body(self.config.request_body_template, prompt, session_id)
        sequence = 0
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds, transport=self.config.transport) as client:
                async with client.stream(self.config.method, self.config.url, json=body, headers=self.config.headers) as response:
                    async for line in response.aiter_lines():
                        raw = _strip_sse_prefix(line)
                        if raw is None:
                            continue
                        sequence += 1
                        frame = _parse_frame(raw)
                        yield self._interpret(frame, sequence)
        except (TargetConnectionError, TargetParseError):
            raise
        except Exception as exc:
            raise TargetConnectionError(f"sse connection to {self.config.url} failed: {exc}") from exc

    async def send(self, prompt: str, session: str | None = None) -> TargetResponse:
        session_id = session or "default"
        session_events = self._trace.setdefault(session_id, [])
        call_trace_events: list[TraceEvent] = []
        text_parts: list[str] = []
        error_message: str | None = None

        async for event in self.events(prompt, session_id):
            trace_event = _to_trace_event(session_id, event)
            session_events.append(trace_event)
            call_trace_events.append(trace_event)

            if event.type == EventType.TOKEN:
                chunk = _extract_text(event.data, self.config.text_field)
                if chunk:
                    text_parts.append(chunk)
            elif event.type == EventType.ERROR:
                error_message = _extract_text(event.data, self.config.text_field) or "sse target reported an error"
                break
            elif event.type == EventType.FINAL:
                final_text = _extract_text(event.data, self.config.text_field)
                if final_text:
                    text_parts.append(final_text)
                break

        if error_message is not None:
            raise TargetParseError(error_message)

        text = "".join(text_parts)
        return TargetResponse(prompt=prompt, text=text, metadata={"session": session_id}, trace_events=call_trace_events)

    async def reset_session(self, session: str | None = None) -> None:
        self._trace.pop(session or "default", None)

    async def trace(self, session: str | None = None) -> list[TraceEvent]:
        if session is None:
            return [event for events in self._trace.values() for event in events]
        return list(self._trace.get(session, []))

    def _interpret(self, frame: dict[str, Any], sequence: int) -> Event:
        frame_type = str(frame.get(self.config.type_field, "token"))
        if frame_type in self.config.final_types:
            kind = EventType.FINAL
        elif frame_type in self.config.error_types:
            kind = EventType.ERROR
        elif frame_type == "retrieval":
            kind = EventType.RETRIEVAL
        elif frame_type == "tool_call":
            kind = EventType.TOOL_CALL
        elif frame_type == "start":
            kind = EventType.START
        else:
            kind = EventType.TOKEN
        return Event(type=kind, sequence=sequence, data=frame)


def _render_body(template: dict[str, Any], prompt: str, session_id: str) -> dict[str, Any]:
    def _render(value: Any) -> Any:
        if isinstance(value, str):
            return value.replace("{{PROMPT}}", prompt).replace("{{SESSION}}", session_id)
        if isinstance(value, dict):
            return {k: _render(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_render(v) for v in value]
        return value

    return _render(template)


def _strip_sse_prefix(line: str) -> str | None:
    """A `text/event-stream` body's meaningful lines are `data: <payload>`
    (blank lines separate events, `event:`/`id:`/`retry:` fields are
    ignored -- this project only needs the payload); a plain
    chunked-JSON-lines stream (no `data:` prefix at all) is also
    accepted so this adapter isn't strictly limited to spec-perfect SSE.
    """
    if not line:
        return None
    if line.startswith("data:"):
        payload = line[len("data:") :].strip()
        return payload or None
    if line.startswith((":", "event:", "id:", "retry:")):
        return None
    return line.strip() or None


def _parse_frame(raw: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {"content": raw}
    return parsed if isinstance(parsed, dict) else {"content": raw}


def _extract_text(frame: dict[str, Any], text_field: str) -> str:
    current: Any = frame
    for part in text_field.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return ""
    return str(current) if current is not None else ""


def _to_trace_event(session_id: str, event: Event) -> TraceEvent:
    return TraceEvent(trace_id=session_id, sequence=event.sequence, event_type=event.type.value, metadata=event.data)
