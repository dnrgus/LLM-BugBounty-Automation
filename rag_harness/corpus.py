from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ControlledDocument:
    document_id: str
    content: str
    source: str = "controlled"
    injection: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def document_hash(self) -> str:
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Chunk:
    chunk_id: str
    document_id: str
    text: str
    document_hash: str
    source: str
    injection: bool


def load_corpus(path: Path | str) -> list[ControlledDocument]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    documents: list[ControlledDocument] = []
    for item in data.get("documents", []):
        documents.append(
            ControlledDocument(
                document_id=item["id"],
                content=item["content"],
                source=item.get("source", "controlled"),
                injection=bool(item.get("injection", False)),
                metadata=item.get("metadata", {}),
            )
        )
    return documents


def chunk_documents(documents: list[ControlledDocument], chunk_size: int = 400) -> list[Chunk]:
    chunks: list[Chunk] = []
    for document in documents:
        text = document.content.strip()
        pieces = [text[i : i + chunk_size] for i in range(0, len(text), chunk_size)] or [text]
        for index, piece in enumerate(pieces):
            chunks.append(
                Chunk(
                    chunk_id=f"{document.document_id}_chunk_{index}",
                    document_id=document.document_id,
                    text=piece,
                    document_hash=document.document_hash,
                    source=document.source,
                    injection=document.injection,
                )
            )
    return chunks


def corpus_hash(documents: list[ControlledDocument]) -> str:
    payload = "|".join(sorted(document.document_hash for document in documents))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
