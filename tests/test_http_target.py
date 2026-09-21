import asyncio
import json

import httpx
import pytest

from targets.errors import (
    TargetAuthenticationError,
    TargetConnectionError,
    TargetParseError,
    TargetRateLimitError,
    TargetServerError,
)
from targets.factory import create_target
from targets.http_target import (
    CustomHTTPAdapter,
    CustomHTTPConfig,
    HTTPTargetConfig,
    OpenAICompatibleTarget,
    extract_json_path,
    openai_target_from_env,
)


def _config(transport: httpx.MockTransport) -> HTTPTargetConfig:
    return HTTPTargetConfig(
        id="test-openai",
        kind="llm",
        provider="openai-compatible",
        name="gpt-test",
        version="gpt-test",
        base_url="https://example-llm.invalid/v1",
        headers={"Authorization": "Bearer test-key"},
        transport=transport,
    )


def _echo_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/models"):
        return httpx.Response(200, json={"data": []})
    body = request.read()
    payload = json.loads(body)
    last_user_message = payload["messages"][-1]["content"]
    return httpx.Response(
        200,
        json={
            "choices": [{"message": {"role": "assistant", "content": f"echo: {last_user_message}"}}],
            "usage": {"total_tokens": 12},
        },
    )


async def _send(target: OpenAICompatibleTarget, prompt: str, session: str | None = None):
    return await target.send(prompt, session=session)


def test_openai_compatible_target_sends_request_and_parses_response() -> None:
    target = OpenAICompatibleTarget(_config(httpx.MockTransport(_echo_handler)))
    response = asyncio.run(_send(target, "hello", session="s1"))
    assert response.text == "echo: hello"
    assert response.metadata["usage"]["total_tokens"] == 12
    assert response.metadata["status_code"] == 200


def test_openai_compatible_target_threads_multi_turn_history() -> None:
    target = OpenAICompatibleTarget(_config(httpx.MockTransport(_echo_handler)))
    asyncio.run(_send(target, "first", session="s1"))
    asyncio.run(_send(target, "second", session="s1"))
    trace = asyncio.run(target.trace("s1"))
    assert [event.event_type for event in trace] == ["llm_call", "llm_call"]
    assert target._sessions["s1"] == [
        {"role": "user", "content": "first"},
        {"role": "assistant", "content": "echo: first"},
        {"role": "user", "content": "second"},
        {"role": "assistant", "content": "echo: second"},
    ]


def test_openai_compatible_target_reset_session_clears_history() -> None:
    target = OpenAICompatibleTarget(_config(httpx.MockTransport(_echo_handler)))
    asyncio.run(_send(target, "hello", session="s1"))
    asyncio.run(target.reset_session("s1"))
    assert target._sessions.get("s1", []) == []
    assert asyncio.run(target.trace("s1")) == []


def test_openai_compatible_target_healthcheck_reports_server_errors() -> None:
    def failing_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    target = OpenAICompatibleTarget(_config(httpx.MockTransport(failing_handler)))
    assert asyncio.run(target.healthcheck()) is False


def test_openai_compatible_target_raises_target_authentication_error_on_401() -> None:
    def unauthorized_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_api_key"})

    target = OpenAICompatibleTarget(_config(httpx.MockTransport(unauthorized_handler)))
    with pytest.raises(TargetAuthenticationError):
        asyncio.run(_send(target, "hello"))


def test_openai_compatible_target_raises_target_rate_limit_error_on_429() -> None:
    def rate_limited_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": "rate_limited"})

    target = OpenAICompatibleTarget(_config(httpx.MockTransport(rate_limited_handler)))
    with pytest.raises(TargetRateLimitError):
        asyncio.run(_send(target, "hello"))


def test_openai_compatible_target_raises_target_connection_error_on_timeout() -> None:
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("simulated timeout", request=request)

    target = OpenAICompatibleTarget(_config(httpx.MockTransport(timeout_handler)))
    with pytest.raises(TargetConnectionError):
        asyncio.run(_send(target, "hello"))


def test_openai_compatible_target_raises_target_parse_error_on_malformed_body() -> None:
    def malformed_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})

    target = OpenAICompatibleTarget(_config(httpx.MockTransport(malformed_handler)))
    with pytest.raises(TargetParseError):
        asyncio.run(_send(target, "hello"))


def test_openai_target_from_env_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        openai_target_from_env()


def test_openai_target_from_env_builds_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://example-llm.invalid/v1")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-test")
    target = openai_target_from_env()
    assert target.config.base_url == "https://example-llm.invalid/v1"
    assert target.config.name == "gpt-test"
    assert target.config.headers["Authorization"] == "Bearer sk-test"


def test_factory_creates_openai_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    target = create_target("openai")
    assert isinstance(target, OpenAICompatibleTarget)


def test_extract_json_path_walks_nested_dicts_and_lists() -> None:
    data = {"choices": [{"message": {"content": "hi"}}], "reply": {"text": "hello"}}
    assert extract_json_path(data, "choices.0.message.content") == "hi"
    assert extract_json_path(data, "reply.text") == "hello"


def test_extract_json_path_raises_target_parse_error_on_missing_key() -> None:
    with pytest.raises(TargetParseError):
        extract_json_path({"reply": {}}, "reply.text")


def _custom_config(transport: httpx.MockTransport, **overrides) -> CustomHTTPConfig:
    defaults = dict(
        id="test-custom",
        kind="llm",
        provider="custom-http",
        name="test-custom",
        version="unknown",
        base_url="https://custom-target.invalid",
        request_path="/api/chat",
        request_body_template={"message": "{{PROMPT}}", "session_id": "{{SESSION}}"},
        response_text_path="reply.text",
        transport=transport,
    )
    defaults.update(overrides)
    return CustomHTTPConfig(**defaults)


def _custom_echo_handler(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.read())
    return httpx.Response(200, json={"reply": {"text": f"custom-echo: {body['message']}"}})


def test_custom_http_adapter_sends_configured_body_and_extracts_response() -> None:
    target = CustomHTTPAdapter(_custom_config(httpx.MockTransport(_custom_echo_handler)))
    response = asyncio.run(target.send("ping", session="s1"))
    assert response.text == "custom-echo: ping"


def test_custom_http_adapter_records_trace_and_history() -> None:
    target = CustomHTTPAdapter(_custom_config(httpx.MockTransport(_custom_echo_handler)))
    asyncio.run(target.send("first", session="s1"))
    asyncio.run(target.send("second", session="s1"))
    trace = asyncio.run(target.trace("s1"))
    assert [event.event_type for event in trace] == ["llm_call", "llm_call"]
    assert target._history["s1"][0] == {"role": "user", "content": "first"}


def test_custom_http_adapter_raises_on_unresolvable_response_path() -> None:
    def wrong_shape_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})

    target = CustomHTTPAdapter(_custom_config(httpx.MockTransport(wrong_shape_handler)))
    with pytest.raises(TargetParseError):
        asyncio.run(target.send("ping"))


def test_custom_http_adapter_raises_target_server_error_on_5xx() -> None:
    def failing_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    target = CustomHTTPAdapter(_custom_config(httpx.MockTransport(failing_handler)))
    with pytest.raises(TargetServerError):
        asyncio.run(target.send("ping"))
