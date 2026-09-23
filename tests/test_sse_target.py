"""P4.3-B HTTP SSE/streaming target (roadmap v4.3.0 Runtime Coverage
Expansion) -- the SSE counterpart to tests/test_websocket_target.py.
"""

import asyncio

import httpx
import pytest

from events.models import EventType
from events.sse_target import SSETargetAdapter, SSETargetConfig
from targets.base import supports_streaming
from targets.errors import TargetParseError


def _sse_body(frames: list[dict]) -> str:
    import json

    return "".join(f"data: {json.dumps(frame)}\n\n" for frame in frames)


def _config(handler, **overrides) -> SSETargetConfig:
    defaults = dict(
        id="sse1", name="sse1", version="1", url="https://lab.example.com/stream", transport=httpx.MockTransport(handler)
    )
    defaults.update(overrides)
    return SSETargetConfig(**defaults)


def test_send_accumulates_token_frames_into_final_text() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = _sse_body(
            [
                {"type": "start"},
                {"type": "token", "content": "Hello, "},
                {"type": "token", "content": "world!"},
                {"type": "final", "content": ""},
            ]
        )
        return httpx.Response(200, text=body, headers={"content-type": "text/event-stream"})

    adapter = SSETargetAdapter(_config(handler))
    response = asyncio.run(adapter.send("hi"))
    assert response.text == "Hello, world!"
    assert len(response.trace_events) == 4


def test_error_frame_raises_target_parse_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = _sse_body([{"type": "start"}, {"type": "error", "content": "boom"}])
        return httpx.Response(200, text=body)

    adapter = SSETargetAdapter(_config(handler))
    with pytest.raises(TargetParseError, match="boom"):
        asyncio.run(adapter.send("hi"))


def test_final_frame_stops_the_stream_early() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = _sse_body([{"type": "final", "content": "done"}, {"type": "token", "content": "should not appear"}])
        return httpx.Response(200, text=body)

    adapter = SSETargetAdapter(_config(handler))
    response = asyncio.run(adapter.send("hi"))
    assert response.text == "done"


def test_events_yields_raw_events_before_send_aggregates_them() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = _sse_body([{"type": "token", "content": "a"}, {"type": "final", "content": "b"}])
        return httpx.Response(200, text=body)

    adapter = SSETargetAdapter(_config(handler))

    async def _collect():
        return [event async for event in adapter.events("hi")]

    events = asyncio.run(_collect())
    assert [event.type for event in events] == [EventType.TOKEN, EventType.FINAL]


def test_sse_adapter_supports_streaming() -> None:
    adapter = SSETargetAdapter(_config(lambda r: httpx.Response(200)))
    assert supports_streaming(adapter) is True


def test_request_body_template_renders_prompt_and_session() -> None:
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content.decode("utf-8")
        return httpx.Response(200, text=_sse_body([{"type": "final", "content": "ok"}]))

    adapter = SSETargetAdapter(
        _config(handler, request_body_template={"message": "{{PROMPT}}", "session_id": "{{SESSION}}"})
    )
    asyncio.run(adapter.send("what is this", session="s1"))
    assert '"message": "what is this"' in captured["body"] or '"message":"what is this"' in captured["body"]
    assert '"session_id": "s1"' in captured["body"] or '"session_id":"s1"' in captured["body"]


def test_reset_session_clears_trace() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=_sse_body([{"type": "final", "content": "ok"}]))

    adapter = SSETargetAdapter(_config(handler))
    asyncio.run(adapter.send("hi", session="s1"))
    asyncio.run(adapter.reset_session("s1"))
    trace = asyncio.run(adapter.trace("s1"))
    assert trace == []


def test_non_data_lines_are_ignored() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = "event: ping\n\ndata: {\"type\": \"final\", \"content\": \"ok\"}\n\n"
        return httpx.Response(200, text=body)

    adapter = SSETargetAdapter(_config(handler))
    response = asyncio.run(adapter.send("hi"))
    assert response.text == "ok"
