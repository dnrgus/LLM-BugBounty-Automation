from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from targets.http_target import _substitute, extract_json_path


class Interaction(Protocol):
    method: str
    request_path: str

    def build_body(self, prompt: str, session_id: str, history: list[dict[str, str]]) -> dict[str, Any]: ...

    def parse_response(self, data: Any) -> str: ...


@dataclass(frozen=True)
class ChatCompletionsInteraction:
    """OpenAI-compatible chat/completions shape: a real messages array
    (prior history + the new turn), not a templated string -- matching
    how targets.http_target.OpenAICompatibleTarget already builds it.
    """

    model: str = "gpt-4o-mini"
    method: str = "POST"
    request_path: str = "/chat/completions"
    response_text_path: str = "choices.0.message.content"

    def build_body(self, prompt: str, session_id: str, history: list[dict[str, str]]) -> dict[str, Any]:
        return {"model": self.model, "messages": [*history, {"role": "user", "content": prompt}]}

    def parse_response(self, data: Any) -> str:
        return str(extract_json_path(data, self.response_text_path))


@dataclass(frozen=True)
class CustomJSONInteraction:
    """An arbitrary bespoke JSON request/response shape, driven by a
    template rendered with {{PROMPT}}, {{SESSION}}, and {{HISTORY_JSON}}
    -- matching targets.http_target.CustomHTTPAdapter's existing scheme.
    """

    method: str = "POST"
    request_path: str = ""
    request_body_template: dict[str, Any] = field(default_factory=lambda: {"message": "{{PROMPT}}"})
    response_text_path: str = "response"

    def build_body(self, prompt: str, session_id: str, history: list[dict[str, str]]) -> dict[str, Any]:
        values = {"PROMPT": prompt, "SESSION": session_id, "HISTORY_JSON": json.dumps(history, ensure_ascii=False)}
        return _substitute(self.request_body_template, values)

    def parse_response(self, data: Any) -> str:
        return str(extract_json_path(data, self.response_text_path))


def build_interaction(config: dict[str, Any]) -> Interaction:
    kind = config.get("type", "custom_json")
    if kind == "chat_completions":
        return ChatCompletionsInteraction(
            model=str(config.get("model", "gpt-4o-mini")),
            method=str(config.get("method", "POST")),
            request_path=str(config.get("path", "/chat/completions")),
            response_text_path=str(config.get("response_text_path", "choices.0.message.content")),
        )
    if kind == "custom_json":
        return CustomJSONInteraction(
            method=str(config.get("method", "POST")),
            request_path=str(config.get("path", "")),
            request_body_template=config.get("request_body_template") or {"message": "{{PROMPT}}"},
            response_text_path=str(config.get("response_text_path", "response")),
        )
    raise ValueError(f"unsupported interaction type: {kind}")
