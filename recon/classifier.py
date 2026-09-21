from __future__ import annotations

from urllib.parse import urlparse

from core.models import Endpoint

CLASSIFICATION_RAG = "rag"
CLASSIFICATION_AGENT = "agent"
CLASSIFICATION_CHAT = "chat"
CLASSIFICATION_AI_API = "ai_api"
CLASSIFICATION_UNKNOWN = "unknown"

_RAG_KEYWORDS = ("rag", "retriev", "vector", "embed", "knowledge")
_AGENT_KEYWORDS = ("agent", "tool", "action")
_CHAT_KEYWORDS = ("chat", "completion", "generate", "assistant")
_AI_TECH_SIGNALS = ("openai", "anthropic", "llm", "gpt", "langchain")


def classify_endpoint(endpoint: Endpoint) -> str:
    """Heuristically classify a discovered endpoint as AI API / Chat / RAG / Agent.

    Offline and deterministic: uses only the URL path and any tech signals the
    recon tools already reported (e.g. httpx's `tech` list), since this
    pipeline never makes live requests to discovered endpoints itself.
    """
    path = urlparse(endpoint.url).path.lower()
    tech = [str(item).lower() for item in (endpoint.metadata or {}).get("tech", []) or []]

    if any(keyword in path for keyword in _RAG_KEYWORDS):
        return CLASSIFICATION_RAG
    if any(keyword in path for keyword in _AGENT_KEYWORDS):
        return CLASSIFICATION_AGENT
    if any(keyword in path for keyword in _CHAT_KEYWORDS):
        return CLASSIFICATION_CHAT
    if any(signal in item for item in tech for signal in _AI_TECH_SIGNALS) or path.startswith("/api/"):
        return CLASSIFICATION_AI_API
    return CLASSIFICATION_UNKNOWN
