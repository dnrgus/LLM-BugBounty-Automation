from __future__ import annotations

from targets.base import TargetAdapter
from targets.fake import FakeAgentTarget, FakeLLMTarget, FakeRAGTarget


def create_target(kind: str) -> TargetAdapter:
    if kind == "fake-llm":
        return FakeLLMTarget()
    if kind == "fake-agent":
        return FakeAgentTarget()
    if kind == "fake-rag":
        return FakeRAGTarget()
    raise ValueError(f"unknown target kind: {kind}")
