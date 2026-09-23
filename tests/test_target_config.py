from pathlib import Path

import pytest

from events.sse_target import SSETargetAdapter
from events.websocket_target import WebSocketTargetAdapter
from manifest.adapter import CompatibilityAdapter
from plugins.browser import BrowserTargetAdapter
from targets.config import load_target
from targets.http_target import CustomHTTPAdapter, OpenAICompatibleTarget

FIXTURES = Path("tests/fixtures/targets")


def test_load_target_builds_openai_compatible_adapter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_TARGET_API_KEY", "sk-test")
    config_path = tmp_path / "openai.yaml"
    config_path.write_text(
        """
target:
  id: lab-openai
  adapter: openai_compatible
  base_url: https://lab.example.com/v1
  model: lab-model
  auth:
    api_key_env: TEST_TARGET_API_KEY
  timeout_seconds: 15
  capabilities:
    chat: true
""",
        encoding="utf-8",
    )
    target = load_target(config_path)
    assert isinstance(target, OpenAICompatibleTarget)
    assert target.config.base_url == "https://lab.example.com/v1"
    assert target.config.name == "lab-model"
    assert target.config.headers["Authorization"] == "Bearer sk-test"
    assert target.config.timeout_seconds == 15


def test_load_target_builds_custom_http_adapter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_TARGET_API_KEY", "cookie-value")
    config_path = tmp_path / "custom.yaml"
    config_path.write_text(
        """
target:
  id: lab-custom
  adapter: custom_http
  base_url: https://lab.example.com
  auth:
    api_key_env: TEST_TARGET_API_KEY
    header_name: X-Session-Token
    header_prefix: ""
  request:
    method: POST
    path: /api/chat
    body_template:
      message: "{{PROMPT}}"
      conversation_id: "{{SESSION}}"
    response_text_path: reply.text
  capabilities:
    chat: true
    rag: true
""",
        encoding="utf-8",
    )
    target = load_target(config_path)
    assert isinstance(target, CustomHTTPAdapter)
    assert target.config.request_path == "/api/chat"
    assert target.config.response_text_path == "reply.text"
    assert target.config.headers["X-Session-Token"] == "cookie-value"


def test_load_target_builds_universal_manifest_adapter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_TARGET_API_KEY", "sk-universal")
    config_path = tmp_path / "universal.yaml"
    config_path.write_text(
        """
target:
  id: lab-universal
  adapter: universal
  base_url: https://lab.example.com
  auth:
    type: bearer
    api_key_env: TEST_TARGET_API_KEY
  interaction:
    type: custom_json
    path: /api/chat
    request_body_template:
      message: "{{PROMPT}}"
    response_text_path: reply.text
  capabilities:
    chat: true
""",
        encoding="utf-8",
    )
    target = load_target(config_path)
    assert isinstance(target, CompatibilityAdapter)
    assert target.config.base_url == "https://lab.example.com"
    assert target.config.interaction.request_path == "/api/chat"
    assert target._auth_headers["Authorization"] == "Bearer sk-universal"


def test_load_target_builds_websocket_adapter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_TARGET_API_KEY", "sk-ws")
    config_path = tmp_path / "websocket.yaml"
    config_path.write_text(
        """
target:
  id: lab-ws
  adapter: websocket
  base_url: wss://lab.example.com/stream
  auth:
    api_key_env: TEST_TARGET_API_KEY
  frame:
    type_field: kind
    text_field: text
    token_types: [chunk]
    final_types: [complete]
  capabilities:
    chat: true
""",
        encoding="utf-8",
    )
    target = load_target(config_path)
    assert isinstance(target, WebSocketTargetAdapter)
    assert target.config.url == "wss://lab.example.com/stream"
    assert target.config.type_field == "kind"
    assert target.config.token_types == ("chunk",)
    assert target.config.extra_headers["Authorization"] == "Bearer sk-ws"


def test_load_target_builds_sse_adapter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_TARGET_API_KEY", "sk-sse")
    config_path = tmp_path / "sse.yaml"
    config_path.write_text(
        """
target:
  id: lab-sse
  adapter: sse
  base_url: https://lab.example.com/stream
  auth:
    api_key_env: TEST_TARGET_API_KEY
  request:
    method: POST
    body_template:
      message: "{{PROMPT}}"
  frame:
    type_field: kind
    text_field: text
    final_types: [complete]
  capabilities:
    chat: true
""",
        encoding="utf-8",
    )
    target = load_target(config_path)
    assert isinstance(target, SSETargetAdapter)
    assert target.config.url == "https://lab.example.com/stream"
    assert target.config.type_field == "kind"
    assert target.config.final_types == ("complete",)
    assert target.config.headers["Authorization"] == "Bearer sk-sse"


def test_load_target_builds_browser_adapter_via_plugin_fallback(tmp_path: Path) -> None:
    # "browser" is not in targets.config._SUPPORTED_ADAPTERS -- this
    # proves U12's plugin-registry fallback, not a hardcoded branch.
    config_path = tmp_path / "browser.yaml"
    config_path.write_text(
        """
target:
  id: lab-browser
  adapter: browser
  base_url: https://chat.example.com
  selectors:
    input: "#chat-input"
    response: "#reply"
""",
        encoding="utf-8",
    )
    target = load_target(config_path)
    assert isinstance(target, BrowserTargetAdapter)
    assert target.config.url == "https://chat.example.com"
    assert target.config.input_selector == "#chat-input"
    assert target.config.response_selector == "#reply"


def test_load_target_requires_api_key_env_to_be_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISSING_TARGET_KEY", raising=False)
    config_path = tmp_path / "target.yaml"
    config_path.write_text(
        """
target:
  adapter: openai_compatible
  base_url: https://lab.example.com/v1
  auth:
    api_key_env: MISSING_TARGET_KEY
""",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="MISSING_TARGET_KEY"):
        load_target(config_path)


def test_load_target_rejects_unsupported_adapter(tmp_path: Path) -> None:
    # "websocket" was this test's example of an unsupported adapter until
    # U11 added real support for it -- use a still-genuinely-unsupported
    # name instead.
    config_path = tmp_path / "bad.yaml"
    config_path.write_text(
        """
target:
  adapter: graphql
  base_url: https://lab.example.com
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unsupported adapter"):
        load_target(config_path)


def test_load_target_requires_base_url(tmp_path: Path) -> None:
    config_path = tmp_path / "no-url.yaml"
    config_path.write_text("target:\n  adapter: openai_compatible\n", encoding="utf-8")
    with pytest.raises(ValueError, match="base_url"):
        load_target(config_path)
