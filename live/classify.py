from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from attack_surface.models import AttackSurfaceItem

TargetKind = Literal["web", "api", "graphql", "llm", "rag", "agent", "websocket"]

_RAG_KEYWORDS = {"rag", "retrieval"}
_AGENT_KEYWORDS = {"agent", "copilot"}
_LLM_PATH_KEYWORDS = ("chat", "completion", "generate", "assistant")


@dataclass(frozen=True)
class ClassifiedCandidate:
    """One capability-typed candidate derived from a single AttackSurfaceItem.

    A single discovery item can produce more than one candidate (e.g. a
    WebSocket URL whose path looks like a chat stream is both a
    "websocket" and an "llm" candidate) -- classification is additive,
    not a forced single label.
    """

    kind: TargetKind
    location: str
    confidence: float
    signals: list[str]
    source_item: AttackSurfaceItem

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "location": self.location,
            "confidence": round(self.confidence, 2),
            "signals": self.signals,
            "source_item_id": self.source_item.id,
        }


def classify_items(items: list[AttackSurfaceItem]) -> list[ClassifiedCandidate]:
    """U5 Auto Profiler (design doc section 7): turns raw LIVE MODE
    discovery output into typed capability candidates -- web / api /
    graphql / llm / rag / agent / websocket.

    Pure classification: no network calls, no probing. See
    live.auto_profile for the step that hands the resulting llm/api
    candidates off to the existing Capability Probe for verification.
    """
    candidates: list[ClassifiedCandidate] = []
    for item in items:
        candidates.extend(_classify_one(item))
    return candidates


def _classify_one(item: AttackSurfaceItem) -> list[ClassifiedCandidate]:
    location_lower = item.location.lower()

    if item.asset_type == "websocket":
        out = [_candidate("websocket", item, item.confidence, ["websocket_url"])]
        if any(keyword in location_lower for keyword in ("chat", "stream", "/ws")):
            out.append(_candidate("llm", item, item.confidence * 0.8, ["websocket_chat_hint"]))
        return out

    if item.asset_type == "llm":
        hints = [str(hint) for hint in item.metadata.get("hints", [])]
        out = []
        if any(keyword in hints for keyword in _RAG_KEYWORDS):
            out.append(_candidate("rag", item, item.confidence, hints))
        if any(keyword in hints for keyword in _AGENT_KEYWORDS):
            out.append(_candidate("agent", item, item.confidence, hints))
        out.append(_candidate("llm", item, item.confidence, hints))
        return out

    if item.asset_type == "endpoint":
        if "/graphql" in location_lower:
            return [_candidate("graphql", item, max(item.confidence, 0.6), ["graphql_path"])]

        if "/api/" in location_lower:
            out = []
            if any(keyword in location_lower for keyword in _LLM_PATH_KEYWORDS):
                out.append(
                    _candidate("llm", item, min(item.confidence + 0.2, 0.95), ["api_path", "llm_path_keyword"])
                )
            out.append(_candidate("api", item, item.confidence, ["api_path"]))
            return out

        return [_candidate("web", item, item.confidence, ["page_fingerprint"])]

    return []


def _candidate(kind: TargetKind, item: AttackSurfaceItem, confidence: float, signals: list[str]) -> ClassifiedCandidate:
    return ClassifiedCandidate(kind=kind, location=item.location, confidence=confidence, signals=signals, source_item=item)
