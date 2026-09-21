import asyncio

import httpx
import pytest

from targets.factory import create_target
from targets.http_target import HTTPTargetConfig, OpenAICompatibleTarget, openai_target_from_env


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
    import json

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


def test_openai_compatible_target_raises_on_http_error_status() -> None:
    def unauthorized_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_api_key"})

    target = OpenAICompatibleTarget(_config(httpx.MockTransport(unauthorized_handler)))
    with pytest.raises(httpx.HTTPStatusError):
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
