import asyncio
import json

import pytest

from events.models import Event, EventType
from events.websocket_target import WebSocketTargetAdapter, WebSocketTargetConfig
from targets.errors import TargetConnectionError, TargetParseError


class _FakeWSConnection:
    def __init__(self, frames: list[dict], sent: list[str]):
        self._frames = frames
        self._sent = sent

    async def send(self, message: str) -> None:
        self._sent.append(message)

    def __aiter__(self):
        self._iter = iter(self._frames)
        return self

    async def __anext__(self):
        try:
            return json.dumps(next(self._iter))
        except StopIteration:
            raise StopAsyncIteration


class _FakeConnector:
    def __init__(self, frames: list[dict] | None = None, sent: list[str] | None = None, fail: bool = False):
        self.frames = frames or []
        self.sent = sent if sent is not None else []
        self.fail = fail

    def __call__(self, url: str, **kwargs):
        self.last_url = url
        self.last_kwargs = kwargs
        return self

    async def __aenter__(self):
        if self.fail:
            raise ConnectionError("simulated connection failure")
        return _FakeWSConnection(self.frames, self.sent)

    async def __aexit__(self, *exc_info):
        return False


def _config(connector: _FakeConnector, **overrides) -> WebSocketTargetConfig:
    defaults = dict(id="ws1", name="ws1", version="1", url="ws://lab.example.com/stream", connector=connector)
    defaults.update(overrides)
    return WebSocketTargetConfig(**defaults)


def test_send_accumulates_token_frames_into_final_text() -> None:
    connector = _FakeConnector(
        frames=[
            {"type": "start"},
            {"type": "token", "content": "Hello, "},
            {"type": "token", "content": "world."},
            {"type": "final", "content": ""},
        ]
    )
    adapter = WebSocketTargetAdapter(_config(connector))

    response = asyncio.run(adapter.send("hi", session="s1"))

    assert response.text == "Hello, world."
    assert json.loads(connector.sent[0]) == {"prompt": "hi", "session": "s1"}


def test_send_records_all_frame_types_as_trace_events() -> None:
    connector = _FakeConnector(
        frames=[
            {"type": "start"},
            {"type": "retrieval", "content": "doc-1"},
            {"type": "tool_call", "content": "search"},
            {"type": "token", "content": "answer"},
            {"type": "final", "content": ""},
        ]
    )
    adapter = WebSocketTargetAdapter(_config(connector))

    response = asyncio.run(adapter.send("hi", session="s1"))

    event_types = [event.event_type for event in response.trace_events]
    assert event_types == ["start", "retrieval", "tool_call", "token", "final"]


def test_send_final_frame_can_carry_trailing_text() -> None:
    connector = _FakeConnector(frames=[{"type": "token", "content": "partial "}, {"type": "final", "content": "end"}])
    adapter = WebSocketTargetAdapter(_config(connector))

    response = asyncio.run(adapter.send("hi"))

    assert response.text == "partial end"


def test_send_error_frame_raises_target_parse_error() -> None:
    connector = _FakeConnector(frames=[{"type": "error", "content": "rate limited"}])
    adapter = WebSocketTargetAdapter(_config(connector))

    with pytest.raises(TargetParseError, match="rate limited"):
        asyncio.run(adapter.send("hi"))


def test_send_connection_failure_raises_target_connection_error() -> None:
    connector = _FakeConnector(fail=True)
    adapter = WebSocketTargetAdapter(_config(connector))

    with pytest.raises(TargetConnectionError):
        asyncio.run(adapter.send("hi"))


def test_healthcheck_true_and_false() -> None:
    ok_adapter = WebSocketTargetAdapter(_config(_FakeConnector(frames=[])))
    assert asyncio.run(ok_adapter.healthcheck()) is True

    bad_adapter = WebSocketTargetAdapter(_config(_FakeConnector(fail=True)))
    assert asyncio.run(bad_adapter.healthcheck()) is False


def test_reset_session_clears_trace() -> None:
    connector = _FakeConnector(frames=[{"type": "final", "content": "ok"}])
    adapter = WebSocketTargetAdapter(_config(connector))
    asyncio.run(adapter.send("hi", session="s1"))
    assert asyncio.run(adapter.trace("s1"))

    asyncio.run(adapter.reset_session("s1"))
    assert asyncio.run(adapter.trace("s1")) == []


def test_metadata_and_capabilities() -> None:
    connector = _FakeConnector()
    adapter = WebSocketTargetAdapter(_config(connector, capabilities={"chat": True, "tools": True}))
    metadata = asyncio.run(adapter.metadata())
    assert metadata.base_url == "ws://lab.example.com/stream"
    capabilities = asyncio.run(adapter.capabilities())
    assert capabilities.tools is True


def test_custom_frame_field_names_are_respected() -> None:
    connector = _FakeConnector(frames=[{"kind": "chunk", "text": "hi"}, {"kind": "complete", "text": ""}])
    adapter = WebSocketTargetAdapter(
        _config(
            connector, type_field="kind", text_field="text", token_types=("chunk",), final_types=("complete",),
        )
    )
    response = asyncio.run(adapter.send("hi"))
    assert response.text == "hi"


def test_event_to_dict_is_json_serializable() -> None:
    event = Event(type=EventType.TOKEN, sequence=1, data={"content": "hi"})
    payload = event.to_dict()
    json.dumps(payload)
    assert payload == {"type": "token", "sequence": 1, "data": {"content": "hi"}}


def test_events_yields_raw_events_that_send_aggregates() -> None:
    connector = _FakeConnector(frames=[{"type": "token", "content": "a"}, {"type": "final", "content": "b"}])
    adapter = WebSocketTargetAdapter(_config(connector))

    async def _collect():
        return [event async for event in adapter.events("hi")]

    events = asyncio.run(_collect())
    assert [event.type for event in events] == [EventType.TOKEN, EventType.FINAL]


def test_websocket_adapter_supports_streaming() -> None:
    from targets.base import supports_streaming

    adapter = WebSocketTargetAdapter(_config(_FakeConnector()))
    assert supports_streaming(adapter) is True
