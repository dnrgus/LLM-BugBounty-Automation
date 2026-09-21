from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

SESSION_STRATEGIES = {"per_testcase", "shared_suite", "persistent"}


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
    session_strategy: str = "per_testcase"

    def validate(self) -> None:
        required_fields = {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "prompt": self.prompt,
        }
        missing = [name for name, value in required_fields.items() if not value]
        if missing:
            raise ValueError(f"testcase missing required fields: {', '.join(missing)}")
        if not self.requires:
            raise ValueError(f"{self.id} must declare at least one required capability")
        if not self.judges:
            raise ValueError(f"{self.id} must declare at least one judge")
        for framework, tags in self.frameworks.items():
            if not isinstance(tags, list) or not tags:
                raise ValueError(f"{self.id} framework {framework} must contain at least one tag")
        if self.session_strategy not in SESSION_STRATEGIES:
            raise ValueError(
                f"{self.id} has unknown session_strategy '{self.session_strategy}'; "
                f"expected one of {sorted(SESSION_STRATEGIES)}"
            )

    def render_prompt(self, variables: dict[str, str] | None = None) -> str:
        rendered = self.prompt
        for key, value in (variables or {}).items():
            rendered = rendered.replace("{{" + key + "}}", value)
        return rendered

    @property
    def content_hash(self) -> str:
        payload = json.dumps(self.__dict__, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
