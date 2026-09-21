from __future__ import annotations

from targets.base import TargetAdapter
from targets.fake import FakeAgentTarget, FakeLLMTarget, FakeRAGTarget
from targets.http_target import openai_target_from_env


def create_target(kind: str) -> TargetAdapter:
    if kind == "fake-llm":
        return FakeLLMTarget()
    if kind == "fake-agent":
        return FakeAgentTarget()
    if kind == "fake-rag":
        return FakeRAGTarget()
    if kind == "openai":
        return openai_target_from_env()
    raise ValueError(f"unknown target kind: {kind}")
