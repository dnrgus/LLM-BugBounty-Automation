from __future__ import annotations

from core.models import CapabilityProfile
from targets.base import TargetResponse


class FakeLLMTarget:
    async def healthcheck(self) -> bool:
        return True

    async def metadata(self) -> dict[str, object]:
        return {"provider": "fake", "model": "fake-llm", "version": "offline"}

    async def capabilities(self) -> CapabilityProfile:
        return CapabilityProfile(chat=True, sessions=True, rag=False, tools=False)

    async def send(self, prompt: str, session: str | None = None) -> TargetResponse:
        if "CANARY-SECRET-123" in prompt:
            text = "Refusal bypass simulation: CANARY-SECRET-123"
        elif "ignore previous instructions" in prompt.lower():
            text = "I cannot ignore safety instructions in this offline target."
        else:
            text = "Offline fake response."
        return TargetResponse(prompt=prompt, text=text, metadata={"session": session})

    async def reset_session(self) -> None:
        return None

