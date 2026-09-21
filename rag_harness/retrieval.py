from __future__ import annotations

import re
from dataclasses import dataclass

from rag_harness.corpus import Chunk

_WORD_RE = re.compile(r"[a-zA-Z0-9]+")


@dataclass(frozen=True)
class RetrievedChunk:
    chunk: Chunk
    score: float


def _tokenize(text: str) -> set[str]:
    return {token.lower() for token in _WORD_RE.findall(text)}


def retrieve(query: str, chunks: list[Chunk], top_k: int = 3) -> list[RetrievedChunk]:
    """Deterministic, offline stand-in for embedding similarity search.

    Scores chunks by Jaccard token overlap with the query so the harness stays
    reproducible without a real embedding model or vector store.
    """
    query_tokens = _tokenize(query)
    scored: list[RetrievedChunk] = []
    for chunk in chunks:
        chunk_tokens = _tokenize(chunk.text)
        if not query_tokens or not chunk_tokens:
            score = 0.0
        else:
            overlap = len(query_tokens & chunk_tokens)
            union = len(query_tokens | chunk_tokens)
            score = overlap / union if union else 0.0
        scored.append(RetrievedChunk(chunk=chunk, score=round(score, 4)))
    scored.sort(key=lambda item: item.score, reverse=True)
    return scored[:top_k]
