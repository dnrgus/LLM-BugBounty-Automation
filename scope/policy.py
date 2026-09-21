from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    action: str = "request"
    mode: str = "execute"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "action": self.action,
            "mode": self.mode,
            "metadata": self.metadata,
        }


class PolicyEngine:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        snapshot = json.dumps(config, sort_keys=True, separators=(",", ":"))
        self.policy_hash = hashlib.sha256(snapshot.encode("utf-8")).hexdigest()

    @classmethod
    def from_yaml(cls, path: Path | str) -> "PolicyEngine":
        with Path(path).open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        return cls(data)

    def validate_url(self, url: str) -> PolicyDecision:
        parsed = urlparse(url)
        domains = self.config.get("scope", {}).get("domains", [])
        patterns = self.config.get("scope", {}).get("url_patterns", [])
        if parsed.hostname not in domains:
            return PolicyDecision(False, "domain out of scope", metadata={"hostname": parsed.hostname})
        if patterns and not any(fnmatch.fnmatch(url, pattern) for pattern in patterns):
            return PolicyDecision(False, "url pattern out of scope", metadata={"url": url})
        if not self.config.get("testing", {}).get("automated_scanning", False):
            return PolicyDecision(False, "automated scanning is disabled")
        return PolicyDecision(True, "in scope", metadata={"url": url})

    def validate_testcase(self, category: str) -> PolicyDecision:
        allowed = bool(self.config.get("testing", {}).get(category, True))
        return PolicyDecision(allowed, "test category allowed" if allowed else "test category denied")

    def decide_action(self, action: str) -> PolicyDecision:
        if action in self.config.get("blocked_actions", []):
            return PolicyDecision(False, "action blocked by program policy", action=action, mode="block")
        if action in self.config.get("approval_required", []):
            return PolicyDecision(False, "approval required", action=action, mode="simulate")
        return PolicyDecision(True, "action allowed", action=action)

    @property
    def max_requests_per_run(self) -> int:
        return int(self.config.get("limits", {}).get("max_requests_per_run", 0) or 0)

