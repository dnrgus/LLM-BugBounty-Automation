from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH"})
DESTRUCTIVE_METHODS = frozenset({"DELETE"})
_STATE_CHANGING_MODES = {"dry_run", "review_required", "allowed"}


def method_risk(method: str) -> str:
    """"read_only" | "state_changing" | "destructive". An unknown verb
    is treated as state-changing -- never assumed safe."""
    normalized = method.strip().upper()
    if normalized in READ_ONLY_METHODS:
        return "read_only"
    if normalized in DESTRUCTIVE_METHODS:
        return "destructive"
    return "state_changing"


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


@dataclass(frozen=True)
class BudgetState:
    max_requests_per_run: int
    requests_used: int
    requests_remaining: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_requests_per_run": self.max_requests_per_run,
            "requests_used": self.requests_used,
            "requests_remaining": self.requests_remaining,
        }


class PolicyEngine:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        snapshot = json.dumps(config, sort_keys=True, separators=(",", ":"))
        self.policy_hash = hashlib.sha256(snapshot.encode("utf-8")).hexdigest()
        self._requests_used = 0

    @classmethod
    def from_yaml(cls, path: Path | str) -> "PolicyEngine":
        with Path(path).open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        return cls(data)

    def validate_url(self, url: str) -> PolicyDecision:
        parsed = urlparse(url)
        scope = self.config.get("scope", {})
        hostname = parsed.hostname or ""
        if parsed.scheme not in {"http", "https", "ws", "wss"}:
            # ws/wss added for U11's generic WebSocket transport -- without
            # them, every WebSocket target would fail Executor's own
            # Policy-Before-Request check regardless of scope config.
            return PolicyDecision(False, "unsupported URL scheme", metadata={"scheme": parsed.scheme})

        denied_domains = scope.get("deny_domains", [])
        denied_patterns = scope.get("deny_url_patterns", [])
        if self._domain_matches(hostname, denied_domains, allow_subdomains=True):
            return PolicyDecision(False, "domain explicitly denied", metadata={"hostname": hostname})
        if self._matches_any(url, denied_patterns):
            return PolicyDecision(False, "url pattern explicitly denied", metadata={"url": url})

        domains = scope.get("domains", [])
        allow_subdomains = bool(scope.get("allow_subdomains", False))
        patterns = scope.get("url_patterns", [])
        if not self._domain_matches(hostname, domains, allow_subdomains=allow_subdomains):
            return PolicyDecision(False, "domain out of scope", metadata={"hostname": hostname})
        if patterns and not self._matches_any(url, patterns):
            return PolicyDecision(False, "url pattern out of scope", metadata={"url": url})
        if not self.config.get("testing", {}).get("automated_scanning", False):
            return PolicyDecision(False, "automated scanning is disabled")
        return PolicyDecision(True, "in scope", metadata={"url": url, "hostname": hostname})

    def validate_domain(self, hostname: str) -> PolicyDecision:
        scope = self.config.get("scope", {})
        denied_domains = scope.get("deny_domains", [])
        if self._domain_matches(hostname, denied_domains, allow_subdomains=True):
            return PolicyDecision(False, "domain explicitly denied", metadata={"hostname": hostname})
        domains = scope.get("domains", [])
        allow_subdomains = bool(scope.get("allow_subdomains", False))
        if not self._domain_matches(hostname, domains, allow_subdomains=allow_subdomains):
            return PolicyDecision(False, "domain out of scope", metadata={"hostname": hostname})
        return PolicyDecision(True, "domain in scope", metadata={"hostname": hostname})

    def validate_redirect(self, source_url: str, redirect_url: str) -> PolicyDecision:
        decision = self.validate_url(redirect_url)
        if decision.allowed:
            return PolicyDecision(
                True,
                "redirect target remains in scope",
                metadata={"source_url": source_url, "redirect_url": redirect_url},
            )
        return PolicyDecision(
            False,
            "redirect target out of scope",
            mode="record-only",
            metadata={"source_url": source_url, "redirect_url": redirect_url, "detail": decision.to_dict()},
        )

    def validate_testcase(self, category: str) -> PolicyDecision:
        allowed = bool(self.config.get("testing", {}).get(category, True))
        return PolicyDecision(allowed, "test category allowed" if allowed else "test category denied")

    def decide_action(self, action: str) -> PolicyDecision:
        if action in self.config.get("blocked_actions", []):
            return PolicyDecision(False, "action blocked by program policy", action=action, mode="block")
        if action in self.config.get("approval_required", []):
            return PolicyDecision(False, "approval required", action=action, mode="simulate")
        return PolicyDecision(True, "action allowed", action=action)

    def decide_method(self, method: str) -> PolicyDecision:
        """P4.5 WP-01 (v5.0 plan 5.1): the one gate every validator asks
        before sending a request with a given HTTP method. Read-only
        methods always execute (scope is still checked separately via
        validate_url). State-changing methods default to "dry_run" --
        the request is planned and recorded, never sent -- unless the
        program config opts in via `testing.state_changing_requests`
        ("dry_run" | "review_required" | "allowed"). DELETE is
        destructive and additionally needs `testing.destructive_actions:
        true`; a "delete" entry in blocked_actions blocks it outright.
        """
        normalized = method.strip().upper()
        risk = method_risk(normalized)
        metadata = {"method": normalized, "risk": risk}
        if risk == "read_only":
            return PolicyDecision(True, "read-only method", action="http_method", metadata=metadata)

        blocked_actions = set(self.config.get("blocked_actions", []))
        if risk == "destructive" and "delete" in blocked_actions:
            return PolicyDecision(False, "delete blocked by program policy", action="http_method", mode="block", metadata=metadata)

        testing = self.config.get("testing", {})
        setting = str(testing.get("state_changing_requests", "dry_run"))
        if setting not in _STATE_CHANGING_MODES:
            setting = "dry_run"
        if setting == "allowed" and risk == "destructive" and not testing.get("destructive_actions", False):
            setting = "review_required"
        if setting == "allowed":
            return PolicyDecision(True, "state-changing method allowed by program policy", action="http_method", metadata=metadata)
        reason = (
            "state-changing method requires human review before sending"
            if setting == "review_required"
            else "state-changing method is dry-run only (planned, never sent)"
        )
        return PolicyDecision(False, reason, action="http_method", mode=setting, metadata=metadata)

    def validate_request(self, url: str, method: str) -> PolicyDecision:
        """Scope + method in one call -- the common gate WP-03's
        `validate` CLI path runs before any request, whatever the
        validator."""
        url_decision = self.validate_url(url)
        if not url_decision.allowed:
            return url_decision
        return self.decide_method(method)

    def consume_request_budget(self, amount: int = 1) -> PolicyDecision:
        if amount < 1:
            raise ValueError("amount must be positive")
        maximum = self.max_requests_per_run
        if maximum and self._requests_used + amount > maximum:
            return PolicyDecision(
                False,
                "request budget exhausted",
                action="request_budget",
                mode="block",
                metadata=self.budget_state.to_dict(),
            )
        self._requests_used += amount
        return PolicyDecision(
            True,
            "request budget available",
            action="request_budget",
            metadata=self.budget_state.to_dict(),
        )

    @property
    def budget_state(self) -> BudgetState:
        maximum = self.max_requests_per_run
        remaining = None if maximum == 0 else max(maximum - self._requests_used, 0)
        return BudgetState(
            max_requests_per_run=maximum,
            requests_used=self._requests_used,
            requests_remaining=remaining,
        )

    @property
    def snapshot(self) -> dict[str, Any]:
        return {
            "program": self.config.get("program"),
            "policy_hash": self.policy_hash,
            "scope": self.config.get("scope", {}),
            "testing": self.config.get("testing", {}),
            "limits": self.config.get("limits", {}),
            "approval_required": self.config.get("approval_required", []),
            "blocked_actions": self.config.get("blocked_actions", []),
        }

    @property
    def max_requests_per_run(self) -> int:
        return int(self.config.get("limits", {}).get("max_requests_per_run", 0) or 0)

    @staticmethod
    def _matches_any(value: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatch(value, pattern) for pattern in patterns)

    @staticmethod
    def _domain_matches(hostname: str, domains: list[str], allow_subdomains: bool) -> bool:
        for domain in domains:
            if hostname == domain:
                return True
            if allow_subdomains and hostname.endswith(f".{domain}"):
                return True
        return False
