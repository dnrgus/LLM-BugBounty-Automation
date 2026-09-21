import asyncio

import pytest

from targets.factory import create_target
from targets.fake import FakeAgentTarget, FakeLLMTarget, FakeRAGTarget


def test_factory_creates_fake_targets() -> None:
    assert isinstance(create_target("fake-llm"), FakeLLMTarget)
    assert isinstance(create_target("fake-agent"), FakeAgentTarget)
    assert isinstance(create_target("fake-rag"), FakeRAGTarget)


def test_factory_rejects_unknown_target() -> None:
    with pytest.raises(ValueError):
        create_target("missing")


async def _agent_tool_trace() -> list[str]:
    target = FakeAgentTarget()
    profile = await target.capabilities()
    assert profile.tools
    assert profile.memory
    response = await target.send("Use tool to search authorized fixture", session="session_1")
    assert response.metadata["session"] == "session_1"
    return [event.event_type for event in await target.trace("session_1")]


def test_fake_agent_records_tool_trace() -> None:
    events = asyncio.run(_agent_tool_trace())
    assert events == ["llm_call", "tool_call", "tool_result", "final_response"]


async def _agent_session_reset() -> int:
    target = FakeAgentTarget()
    await target.send("remember: scoped note", session="session_1")
    await target.reset_session("session_1")
    return len(await target.trace("session_1"))


def test_fake_agent_resets_session_trace() -> None:
    assert asyncio.run(_agent_session_reset()) == 0


async def _rag_retrieval_trace() -> list[str]:
    target = FakeRAGTarget()
    profile = await target.capabilities()
    assert profile.rag
    await target.send("Summarize controlled document", session="rag_session")
    return [event.event_type for event in await target.trace("rag_session")]


def test_fake_rag_records_retrieval_trace() -> None:
    assert asyncio.run(_rag_retrieval_trace()) == ["llm_call", "retrieval", "final_response"]

