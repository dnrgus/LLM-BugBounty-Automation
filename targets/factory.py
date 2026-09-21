from __future__ import annotations

from pathlib import Path

from targets.base import TargetAdapter
from targets.config import load_target
from targets.fake import FakeAgentTarget, FakeLLMTarget, FakeRAGTarget
from targets.http_target import openai_target_from_env


def create_target(kind: str, target_config: Path | str | None = None) -> TargetAdapter:
    if target_config is not None:
        return load_target(target_config)
    if kind == "fake-llm":
        return FakeLLMTarget()
    if kind == "fake-agent":
        return FakeAgentTarget()
    if kind == "fake-rag":
        return FakeRAGTarget()
    if kind == "openai":
        return openai_target_from_env()
    raise ValueError(f"unknown target kind: {kind}")
