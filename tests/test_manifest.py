import asyncio

import httpx
import pytest

from manifest.adapter import CompatibilityAdapter, ManifestTargetConfig
from manifest.auth import ApiKeyHeaderAuth, BasicAuth, BearerTokenAuth, NoAuth, build_auth
from manifest.interaction import ChatCompletionsInteraction, CustomJSONInteraction, build_interaction
from manifest.session import build_session_policy


def test_build_auth_none() -> None:
    assert isinstance(build_auth({}), NoAuth)
    assert build_auth({"type": "none"}).headers() == {}


def test_build_auth_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MANIFEST_TEST_KEY", "sk-abc")
    auth = build_auth({"type": "bearer", "api_key_env": "MANIFEST_TEST_KEY"})
    assert isinstance(auth, BearerTokenAuth)
    assert auth.headers() == {"Authorization": "Bearer sk-abc"}


def test_build_auth_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MANIFEST_TEST_KEY", "abc123")
    auth = build_auth({"type": "api_key", "api_key_env": "MANIFEST_TEST_KEY", "header_name": "X-Api-Key"})
    assert isinstance(auth, ApiKeyHeaderAuth)
    assert auth.headers() == {"X-Api-Key": "abc123"}


def test_build_auth_basic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MANIFEST_TEST_USER", "alice")
    monkeypatch.setenv("MANIFEST_TEST_PASS", "hunter2")
    auth = build_auth({"type": "basic", "username_env": "MANIFEST_TEST_USER", "password_env": "MANIFEST_TEST_PASS"})
    assert isinstance(auth, BasicAuth)
    headers = auth.headers()
    assert headers["Authorization"].startswith("Basic ")


def test_build_auth_missing_env_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MANIFEST_MISSING_KEY", raising=False)
    auth = build_auth({"type": "bearer", "api_key_env": "MANIFEST_MISSING_KEY"})
    with pytest.raises(RuntimeError, match="MANIFEST_MISSING_KEY"):
        auth.headers()


def test_build_auth_unsupported_type_raises() -> None:
    with pytest.raises(ValueError, match="unsupported auth type"):
        build_auth({"type": "hmac"})


def test_build_interaction_chat_completions_builds_a_real_messages_array() -> None:
    interaction = build_interaction({"type": "chat_completions", "model": "gpt-test"})
    assert isinstance(interaction, ChatCompletionsInteraction)
    body = interaction.build_body("hello", "s1", [{"role": "user", "content": "prior"}])
    assert body == {
        "model": "gpt-test",
        "messages": [{"role": "user", "content": "prior"}, {"role": "user", "content": "hello"}],
    }


def test_build_interaction_custom_json_renders_template() -> None:
    interaction = build_interaction(
        {"type": "custom_json", "request_body_template": {"message": "{{PROMPT}}", "sid": "{{SESSION}}"}}
    )
    assert isinstance(interaction, CustomJSONInteraction)
    body = interaction.build_body("hi", "session-1", [])
    assert body == {"message": "hi", "sid": "session-1"}


def test_build_interaction_unsupported_type_raises() -> None:
    with pytest.raises(ValueError, match="unsupported interaction type"):
        build_interaction({"type": "graphql"})


def test_build_session_policy_defaults_stateful() -> None:
    assert build_session_policy({}).stateful is True
    assert build_session_policy({"stateful": False}).stateful is False


def _chat_handler(request: httpx.Request) -> httpx.Response:
    import json as _json

    body = _json.loads(request.read())
    return httpx.Response(200, json={"reply": {"text": f"echo: {body['message']}"}})


def test_compatibility_adapter_end_to_end_custom_json() -> None:
    interaction = build_interaction(
        {"type": "custom_json", "path": "/api/chat", "request_body_template": {"message": "{{PROMPT}}"},
         "response_text_path": "reply.text"}
    )
    config = ManifestTargetConfig(
        id="t1", name="t1", version="1", base_url="https://lab.example.com",
        auth=NoAuth(), interaction=interaction, session_policy=build_session_policy({}),
        transport=httpx.MockTransport(_chat_handler),
    )
    adapter = CompatibilityAdapter(config)

    response = asyncio.run(adapter.send("hello", session="s1"))
    assert response.text == "echo: hello"


def test_compatibility_adapter_metadata_reports_full_endpoint() -> None:
    interaction = build_interaction({"type": "custom_json", "path": "/api/chat"})
    config = ManifestTargetConfig(
        id="t1", name="t1", version="1", base_url="https://lab.example.com/",
        auth=NoAuth(), interaction=interaction, session_policy=build_session_policy({}),
    )
    adapter = CompatibilityAdapter(config)
    metadata = asyncio.run(adapter.metadata())
    assert metadata.base_url == "https://lab.example.com/api/chat"


def test_compatibility_adapter_stateful_session_replays_history() -> None:
    seen_bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json

        body = _json.loads(request.read())
        seen_bodies.append(body)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    interaction = build_interaction({"type": "chat_completions"})
    config = ManifestTargetConfig(
        id="t1", name="t1", version="1", base_url="https://lab.example.com",
        auth=NoAuth(), interaction=interaction, session_policy=build_session_policy({"stateful": True}),
        transport=httpx.MockTransport(handler),
    )
    adapter = CompatibilityAdapter(config)

    asyncio.run(adapter.send("turn one", session="s1"))
    asyncio.run(adapter.send("turn two", session="s1"))

    assert len(seen_bodies[1]["messages"]) == 3  # turn-one user + turn-one assistant + turn-two user


def test_compatibility_adapter_stateless_session_never_replays_history() -> None:
    seen_bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json

        body = _json.loads(request.read())
        seen_bodies.append(body)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    interaction = build_interaction({"type": "chat_completions"})
    config = ManifestTargetConfig(
        id="t1", name="t1", version="1", base_url="https://lab.example.com",
        auth=NoAuth(), interaction=interaction, session_policy=build_session_policy({"stateful": False}),
        transport=httpx.MockTransport(handler),
    )
    adapter = CompatibilityAdapter(config)

    asyncio.run(adapter.send("turn one", session="s1"))
    asyncio.run(adapter.send("turn two", session="s1"))

    assert len(seen_bodies[1]["messages"]) == 1


def test_compatibility_adapter_reset_session_clears_history() -> None:
    interaction = build_interaction({"type": "chat_completions"})
    config = ManifestTargetConfig(
        id="t1", name="t1", version="1", base_url="https://lab.example.com",
        auth=NoAuth(), interaction=interaction, session_policy=build_session_policy({}),
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})),
    )
    adapter = CompatibilityAdapter(config)
    asyncio.run(adapter.send("hi", session="s1"))
    asyncio.run(adapter.reset_session("s1"))
    assert adapter._history.get("s1") is None


def test_compatibility_adapter_sends_auth_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MANIFEST_ADAPTER_TEST_KEY", "sk-test")
    seen_headers = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(dict(request.headers))
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    config = ManifestTargetConfig(
        id="t1", name="t1", version="1", base_url="https://lab.example.com",
        auth=BearerTokenAuth(api_key_env="MANIFEST_ADAPTER_TEST_KEY"),
        interaction=build_interaction({"type": "chat_completions"}),
        session_policy=build_session_policy({}), transport=httpx.MockTransport(handler),
    )
    adapter = CompatibilityAdapter(config)

    asyncio.run(adapter.send("hi", session="s1"))
    assert seen_headers[0]["authorization"] == "Bearer sk-test"
