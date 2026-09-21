from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Testcase:
    id: str
    name: str
    category: str
    requires: list[str]
    prompt: str
    judges: list[str]
    frameworks: dict[str, list[str]] = field(default_factory=dict)
    reproduce: dict[str, Any] = field(default_factory=dict)
    severity: dict[str, str] = field(default_factory=lambda: {"base": "medium"})
    mutation: dict[str, Any] = field(default_factory=dict)

    @property
    def content_hash(self) -> str:
        payload = json.dumps(self.__dict__, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

