from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class BudgetDecision:
    allowed: bool
    reason: str
    usage: dict[str, object] = field(default_factory=dict)


class AttackBudget:
    """Tracks request/token/cost/runtime spend against configured limits.

    Mirrors the design doc's Executor step "Budget.reserve() -> ... ->
    Budget.commit_usage()": call check() before executing a testcase and
    commit_usage() after judging its response. A scan stops itself rather
    than running unbounded against a real target.

    cost_usd tracking is a pass-through only -- this project does not know
    per-provider token pricing, so callers that can't supply a real cost
    should just never call commit_usage(cost_usd=...), leaving max_cost_usd
    effectively unenforced rather than reporting a misleading number.
    """

    def __init__(
        self,
        max_requests: int | None = None,
        max_tokens: int | None = None,
        max_cost_usd: float | None = None,
        max_runtime_minutes: float | None = None,
        per_suite_requests: dict[str, int] | None = None,
    ):
        self.max_requests = max_requests
        self.max_tokens = max_tokens
        self.max_cost_usd = max_cost_usd
        self.max_runtime_minutes = max_runtime_minutes
        self.per_suite_requests = dict(per_suite_requests or {})

        self.requests_used = 0
        self.tokens_used = 0
        self.cost_used_usd = 0.0
        self.per_suite_used: dict[str, int] = {}
        self._started_at = time.monotonic()
        self.stop_reason: str | None = None

    def check(self, category: str | None = None) -> BudgetDecision:
        if self.stop_reason:
            return BudgetDecision(False, self.stop_reason, self.usage)
        if self.max_requests is not None and self.requests_used >= self.max_requests:
            self.stop_reason = "budget_exhausted:requests"
        elif self.max_tokens is not None and self.tokens_used >= self.max_tokens:
            self.stop_reason = "budget_exhausted:tokens"
        elif self.max_cost_usd is not None and self.cost_used_usd >= self.max_cost_usd:
            self.stop_reason = "budget_exhausted:cost"
        elif self.max_runtime_minutes is not None and self.elapsed_minutes >= self.max_runtime_minutes:
            self.stop_reason = "budget_exhausted:runtime"
        if self.stop_reason:
            return BudgetDecision(False, self.stop_reason, self.usage)

        if category is not None and category in self.per_suite_requests:
            used = self.per_suite_used.get(category, 0)
            if used >= self.per_suite_requests[category]:
                return BudgetDecision(False, f"budget_exhausted:suite:{category}", self.usage)
        return BudgetDecision(True, "budget available", self.usage)

    def commit_usage(self, category: str | None = None, tokens: int = 0, cost_usd: float = 0.0) -> None:
        self.requests_used += 1
        self.tokens_used += tokens
        self.cost_used_usd += cost_usd
        if category is not None:
            self.per_suite_used[category] = self.per_suite_used.get(category, 0) + 1

    @property
    def elapsed_minutes(self) -> float:
        return (time.monotonic() - self._started_at) / 60

    @property
    def usage(self) -> dict[str, object]:
        return {
            "requests_used": self.requests_used,
            "tokens_used": self.tokens_used,
            "cost_used_usd": self.cost_used_usd,
            "elapsed_minutes": round(self.elapsed_minutes, 3),
            "per_suite_used": dict(self.per_suite_used),
            "stop_reason": self.stop_reason,
        }
