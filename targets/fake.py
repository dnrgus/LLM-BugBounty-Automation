from __future__ import annotations

from collections import defaultdict

from core.models import CapabilityProfile, TraceEvent
from targets.base import TargetMetadata, TargetResponse


class _TraceBuffer:
    def __init__(self) -> None:
        self._events: dict[str, list[TraceEvent]] = defaultdict(list)

    def add(self, session: str | None, event_type: str, metadata: dict[str, object]) -> TraceEvent:
        session_id = session or "default"
        event = TraceEvent(
            trace_id=session_id,
            sequence=len(self._events[session_id]) + 1,
            event_type=event_type,
            metadata=metadata,
        )
        self._events[session_id].append(event)
        return event

    def list(self, session: str | None = None) -> list[TraceEvent]:
        if session is None:
            return [event for events in self._events.values() for event in events]
        return list(self._events.get(session, []))

    def reset(self, session: str | None = None) -> None:
        if session is None:
            self._events.clear()
            return
        self._events.pop(session, None)


class FakeLLMTarget:
    def __init__(self) -> None:
        self._trace = _TraceBuffer()

    async def healthcheck(self) -> bool:
        return True

    async def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            id="fake-llm",
            kind="llm",
            provider="fake",
            name="fake-llm",
            version="offline",
            base_url="https://ai.example.com/api/chat",
        )

    async def capabilities(self) -> CapabilityProfile:
        return CapabilityProfile(chat=True, sessions=True, rag=False, tools=False)

    async def send(self, prompt: str, session: str | None = None) -> TargetResponse:
        events = [self._trace.add(session, "llm_call", {"prompt_length": len(prompt)})]
        if "CANARY-SECRET-123" in prompt:
            text = "Refusal bypass simulation: CANARY-SECRET-123"
        elif "ignore previous instructions" in prompt.lower():
            text = "I cannot ignore safety instructions in this offline target."
        else:
            text = "Offline fake response."
        events.append(self._trace.add(session, "final_response", {"length": len(text)}))
        return TargetResponse(prompt=prompt, text=text, metadata={"session": session}, trace_events=events)

    async def reset_session(self, session: str | None = None) -> None:
        self._trace.reset(session)

    async def trace(self, session: str | None = None) -> list[TraceEvent]:
        return self._trace.list(session)


class FakeAgentTarget:
    def __init__(self) -> None:
        self._trace = _TraceBuffer()
        self.memory: dict[str, str] = {}

    async def healthcheck(self) -> bool:
        return True

    async def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            id="fake-agent",
            kind="agent",
            provider="fake",
            name="fake-agent",
            version="offline",
            base_url="https://ai.example.com/api/agent",
        )

    async def capabilities(self) -> CapabilityProfile:
        return CapabilityProfile(chat=True, sessions=True, tools=True, memory=True)

    async def send(self, prompt: str, session: str | None = None) -> TargetResponse:
        events = [self._trace.add(session, "llm_call", {"prompt_length": len(prompt)})]
        if "remember:" in prompt.lower():
            value = prompt.split(":", 1)[-1].strip()
            self.memory[session or "default"] = value
            events.append(self._trace.add(session, "memory_write", {"key": "session_note"}))
            text = "Stored session note."
        elif "use tool" in prompt.lower():
            events.append(
                self._trace.add(
                    session,
                    "tool_call",
                    {"tool": "offline_search", "arguments": {"query": "authorized test"}},
                )
            )
            events.append(self._trace.add(session, "tool_result", {"tool": "offline_search", "result_count": 1}))
            text = "Tool result summarized from offline fixture."
        else:
            events.append(self._trace.add(session, "memory_read", {"hit": session in self.memory}))
            text = "Agent offline response."
        events.append(self._trace.add(session, "final_response", {"length": len(text)}))
        return TargetResponse(prompt=prompt, text=text, metadata={"session": session}, trace_events=events)

    async def reset_session(self, session: str | None = None) -> None:
        self._trace.reset(session)
        if session is None:
            self.memory.clear()
        else:
            self.memory.pop(session, None)

    async def trace(self, session: str | None = None) -> list[TraceEvent]:
        return self._trace.list(session)


class FakeRAGTarget:
    def __init__(self) -> None:
        self._trace = _TraceBuffer()

    async def healthcheck(self) -> bool:
        return True

    async def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            id="fake-rag",
            kind="rag",
            provider="fake",
            name="fake-rag",
            version="offline",
            base_url="https://ai.example.com/api/rag",
        )

    async def capabilities(self) -> CapabilityProfile:
        return CapabilityProfile(chat=True, sessions=True, rag=True)

    async def send(self, prompt: str, session: str | None = None) -> TargetResponse:
        events = [self._trace.add(session, "llm_call", {"prompt_length": len(prompt)})]
        events.append(
            self._trace.add(
                session,
                "retrieval",
                {"document_id": "doc_safe_1", "chunk_id": "chunk_1", "score": 0.92},
            )
        )
        text = "RAG offline response grounded in controlled document."
        events.append(self._trace.add(session, "final_response", {"length": len(text)}))
        return TargetResponse(prompt=prompt, text=text, metadata={"session": session}, trace_events=events)

    async def reset_session(self, session: str | None = None) -> None:
        self._trace.reset(session)

    async def trace(self, session: str | None = None) -> list[TraceEvent]:
        return self._trace.list(session)
