import asyncio
import json
from pathlib import Path

import httpx

from core.models import Run
from core.orchestrator import run_profile_target
from core.profiler import profile_target
from executor.runner import Executor
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from targets.fake import FakeAgentTarget, FakeLLMTarget
from targets.http_target import HTTPTargetConfig, OpenAICompatibleTarget


def _policy() -> PolicyEngine:
    return PolicyEngine.from_yaml("config/scope.example.yaml")


def test_profile_target_flags_declared_sessions_without_observed_memory(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "profiler.sqlite")
    store.initialize()
    target = FakeAgentTarget()
    executor = Executor(policy=_policy(), target=target, store=store, target_id="fake-agent")

    run = Run(target_id="fake-agent", policy_hash=_policy().policy_hash, fingerprint="profile")
    store.insert_run(run)
    profile = asyncio.run(profile_target(executor, target, run, store))
    assert profile.reachable is True
    assert profile.declared_capabilities.sessions is True
    assert profile.observed_multi_turn is False
    assert any("did not recall" in note for note in profile.notes)


def test_profile_target_skips_active_probing_when_disabled(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "profiler_noprobe.sqlite")
    store.initialize()
    target = FakeLLMTarget()
    executor = Executor(policy=_policy(), target=target, store=store, target_id="fake-llm")

    run = Run(target_id="fake-llm", policy_hash=_policy().policy_hash, fingerprint="profile")
    store.insert_run(run)
    profile = asyncio.run(profile_target(executor, target, run, store, probe=False))
    assert profile.reachable is True
    assert profile.observed_multi_turn is None
    assert profile.probe_response_sample is None


def _memory_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/models"):
        return httpx.Response(200, json={"data": []})
    body = json.loads(request.read())
    messages = body["messages"]
    history_text = " ".join(m["content"] for m in messages)
    if "42" in history_text and "what number" in messages[-1]["content"].lower():
        text = "You asked me to remember 42."
    else:
        text = "Sure, I'll remember that."
    return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": text}}]})


def test_profile_target_confirms_genuine_multi_turn_memory(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "profiler_real.sqlite")
    store.initialize()
    config = HTTPTargetConfig(
        id="mock-openai",
        kind="llm",
        provider="openai-compatible",
        name="mock-model",
        version="mock-model",
        base_url="https://ai.example.com/api",
        capabilities={"chat": True, "sessions": True},
        transport=httpx.MockTransport(_memory_handler),
    )
    target = OpenAICompatibleTarget(config)
    executor = Executor(policy=_policy(), target=target, store=store, target_id="mock-openai")

    run = Run(target_id="mock-openai", policy_hash=_policy().policy_hash, fingerprint="profile")
    store.insert_run(run)
    profile = asyncio.run(profile_target(executor, target, run, store))
    assert profile.observed_multi_turn is True
    assert profile.notes == []


def test_run_profile_target_returns_a_dict(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "profiler_run.sqlite")
    result = asyncio.run(run_profile_target(_policy(), store, target_kind="fake-llm"))
    assert result["target_id"] == "fake-llm"
    assert result["reachable"] is True
    assert "capabilities" in result
