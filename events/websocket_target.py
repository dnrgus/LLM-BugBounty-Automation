from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

from core.models import CapabilityProfile, TraceEvent
from events.models import Event, EventType
from targets.base import TargetMetadata, TargetResponse
from targets.errors import TargetConnectionError, TargetParseError


@dataclass(frozen=True)
class WebSocketTargetConfig:
    """type_field/text_field/*_types make the frame shape configurable,
    since different WS-based LLM/agent APIs disagree on it -- the same
    "don't assume one vendor's exact JSON shape" reasoning
    CustomJSONInteraction already applies to plain HTTP targets.
    """

    id: str
    name: str
    version: str
    url: str
    type_field: str = "type"
    text_field: str = "content"
    token_types: tuple[str, ...] = ("token", "delta")
    final_types: tuple[str, ...] = ("final", "done", "end")
    error_types: tuple[str, ...] = ("error",)
    capabilities: dict[str, bool] = field(default_factory=lambda: {"chat": True})
    timeout_seconds: float = 30.0
    extra_headers: dict[str, str] = field(default_factory=dict)
    connector: Callable[..., Any] | None = None  # injectable websockets.connect-alike, for tests


class WebSocketTargetAdapter:
    """U11 generic WebSocket transport (design doc section 13): connects
    to an arbitrary WS-based streaming target, sends one JSON prompt
    frame, and interprets the resulting frame stream as a formal Event
    sequence (START/TOKEN/RETRIEVAL/TOOL_CALL/FINAL/ERROR) instead of
    assuming any one vendor's exact shape.

    Implements the same TargetAdapter protocol every other adapter in
    this project does, so it slots into the existing Executor/pipeline
    completely unchanged -- send() still returns one TargetResponse; the
    Event stream for that call becomes its trace_events.
    """

    def __init__(self, config: WebSocketTargetConfig):
        self.config = config
        self._trace: dict[str, list[TraceEvent]] = {}

    async def healthcheck(self) -> bool:
        try:
            async with self._connect():
                return True
        except Exception:
            return False

    async def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            id=self.config.id,
            kind="llm",
            provider="websocket-generic",
            name=self.config.name,
            version=self.config.version,
            base_url=self.config.url,
        )

    async def capabilities(self) -> CapabilityProfile:
        return CapabilityProfile(**self.config.capabilities)

    async def send(self, prompt: str, session: str | None = None) -> TargetResponse:
        session_id = session or "default"
        session_events = self._trace.setdefault(session_id, [])
        call_trace_events: list[TraceEvent] = []
        text_parts: list[str] = []
        error_message: str | None = None

        try:
            async with self._connect() as websocket:
                await websocket.send(json.dumps({"prompt": prompt, "session": session_id}))
                async for raw in websocket:
                    frame = json.loads(raw)
                    event = self._interpret(frame, len(session_events) + 1)
                    trace_event = _to_trace_event(session_id, event)
                    session_events.append(trace_event)
                    call_trace_events.append(trace_event)

                    if event.type == EventType.TOKEN:
                        chunk = _extract_text(frame, self.config.text_field)
                        if chunk:
                            text_parts.append(chunk)
                    elif event.type == EventType.ERROR:
                        error_message = _extract_text(frame, self.config.text_field) or "websocket target reported an error"
                        break
                    elif event.type == EventType.FINAL:
                        final_text = _extract_text(frame, self.config.text_field)
                        if final_text:
                            text_parts.append(final_text)
                        break
        except (TargetConnectionError, TargetParseError):
            raise
        except Exception as exc:
            raise TargetConnectionError(f"websocket connection to {self.config.url} failed: {exc}") from exc

        if error_message is not None:
            raise TargetParseError(error_message)

        text = "".join(text_parts)
        return TargetResponse(
            prompt=prompt, text=text, metadata={"session": session_id}, trace_events=call_trace_events
        )

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

    def _connect(self) -> Any:
        import websockets

        connector = self.config.connector or websockets.connect
        kwargs: dict[str, Any] = {"open_timeout": self.config.timeout_seconds}
        if self.config.extra_headers:
            kwargs["additional_headers"] = self.config.extra_headers
        return connector(self.config.url, **kwargs)


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
