"""Shared contract tests every TargetAdapter must satisfy.

Design doc Definition of Done: "Adapter contract test를 통과" -- rather than
each adapter having its own bespoke interface assertions, this runs the same
checks against every adapter kind (Fake* directly, the two real HTTP
adapters via httpx.MockTransport so nothing touches the network).
"""

import asyncio
import json

import httpx
import pytest

from targets.fake import FakeAgentTarget, FakeLLMTarget, FakeRAGTarget
from targets.http_target import CustomHTTPAdapter, CustomHTTPConfig, HTTPTargetConfig, OpenAICompatibleTarget


def _openai_echo_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/models"):
        return httpx.Response(200, json={"data": []})
    body = json.loads(request.read())
    last_message = body["messages"][-1]["content"]
    return httpx.Response(
        200, json={"choices": [{"message": {"role": "assistant", "content": f"echo: {last_message}"}}]}
    )


def _make_openai_target() -> OpenAICompatibleTarget:
    config = HTTPTargetConfig(
        id="contract-openai",
        kind="llm",
        provider="openai-compatible",
        name="contract-model",
        version="contract-model",
        base_url="https://contract-openai.invalid",
        transport=httpx.MockTransport(_openai_echo_handler),
    )
    return OpenAICompatibleTarget(config)


def _custom_echo_handler(request: httpx.Request) -> httpx.Response:
    if request.method == "GET":
        return httpx.Response(200)
    body = json.loads(request.read())
    return httpx.Response(200, json={"reply": {"text": f"echo: {body['message']}"}})


def _make_custom_http_target() -> CustomHTTPAdapter:
    config = CustomHTTPConfig(
        id="contract-custom",
        kind="llm",
        provider="custom-http",
        name="contract-custom",
        version="unknown",
        base_url="https://contract-custom.invalid",
        request_path="/chat",
        response_text_path="reply.text",
        transport=httpx.MockTransport(_custom_echo_handler),
    )
    return CustomHTTPAdapter(config)


TARGET_FACTORIES = {
    "fake-llm": FakeLLMTarget,
    "fake-agent": FakeAgentTarget,
    "fake-rag": FakeRAGTarget,
    "openai-compatible": _make_openai_target,
    "custom-http": _make_custom_http_target,
}


@pytest.mark.parametrize("factory", TARGET_FACTORIES.values(), ids=TARGET_FACTORIES.keys())
def test_adapter_metadata_contract(factory) -> None:
    target = factory()
    metadata = asyncio.run(target.metadata())
    assert metadata.id
    assert metadata.kind
    assert metadata.provider
    assert metadata.name
    assert metadata.version
    assert metadata.base_url


@pytest.mark.parametrize("factory", TARGET_FACTORIES.values(), ids=TARGET_FACTORIES.keys())
def test_adapter_capabilities_contract(factory) -> None:
    target = factory()
    capabilities = asyncio.run(target.capabilities())
    assert isinstance(capabilities.chat, bool)
    assert isinstance(capabilities.sessions, bool)
    assert isinstance(capabilities.to_dict(), dict)


@pytest.mark.parametrize("factory", TARGET_FACTORIES.values(), ids=TARGET_FACTORIES.keys())
def test_adapter_healthcheck_contract(factory) -> None:
    target = factory()
    reachable = asyncio.run(target.healthcheck())
    assert isinstance(reachable, bool)
    assert reachable is True


@pytest.mark.parametrize("factory", TARGET_FACTORIES.values(), ids=TARGET_FACTORIES.keys())
def test_adapter_send_and_trace_contract(factory) -> None:
    async def _run():
        target = factory()
        session = "contract-session"
        before = await target.trace(session)
        response = await target.send("contract probe", session=session)
        after = await target.trace(session)
        return before, response, after

    before, response, after = asyncio.run(_run())
    assert before == []
    assert response.prompt == "contract probe"
    assert isinstance(response.text, str)
    assert response.text != ""
    assert len(after) > 0


@pytest.mark.parametrize("factory", TARGET_FACTORIES.values(), ids=TARGET_FACTORIES.keys())
def test_adapter_reset_session_clears_trace_contract(factory) -> None:
    async def _run():
        target = factory()
        session = "contract-reset-session"
        await target.send("contract probe", session=session)
        await target.reset_session(session)
        return await target.trace(session)

    trace = asyncio.run(_run())
    assert trace == []


@pytest.mark.parametrize("factory", TARGET_FACTORIES.values(), ids=TARGET_FACTORIES.keys())
def test_adapter_send_without_explicit_session_does_not_raise(factory) -> None:
    target = factory()
    response = asyncio.run(target.send("contract probe without session"))
    assert isinstance(response.text, str)
