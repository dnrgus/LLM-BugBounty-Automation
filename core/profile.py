from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from executor.runner import ExecutorOptions


@dataclass(frozen=True)
class PipelineProfile:
    name: str
    testcase_limit: int
    judges: list[str]
    executor: ExecutorOptions
    reproduction_attempts: int
    reproduction_threshold: int
    mutation_enabled: bool
    mutation_strategies: list[str]
    targets: list[str] = field(default_factory=list)
    stages: list[str] = field(default_factory=lambda: ["scan"])
    budget_max_requests: int | None = None
    budget_max_tokens: int | None = None
    budget_max_cost_usd: float | None = None
    budget_max_runtime_minutes: float | None = None
    budget_per_suite: dict[str, int] = field(default_factory=dict)


def load_profile(name: str, path: Path | str = "config/pipeline.yaml") -> PipelineProfile:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    profiles = data.get("profiles", {})
    if name not in profiles:
        raise ValueError(f"unknown pipeline profile: {name}")
    raw = profiles[name]
    executor_raw = raw.get("executor", {})
    reproduction_raw = raw.get("reproduction", {})
    mutation_raw = raw.get("mutation", {})
    budget_raw = raw.get("budget", {})
    attempts = int(reproduction_raw.get("attempts", 1) or 1)
    return PipelineProfile(
        name=name,
        testcase_limit=int(raw.get("testcase_limit", 0) or 0),
        judges=list(raw.get("judges", [])),
        executor=ExecutorOptions(
            timeout_seconds=float(executor_raw.get("timeout_seconds", 10.0)),
            max_attempts=int(executor_raw.get("max_attempts", 1)),
            retry_backoff_seconds=float(executor_raw.get("retry_backoff_seconds", 0.0)),
        ),
        reproduction_attempts=attempts,
        reproduction_threshold=int(reproduction_raw.get("threshold", attempts) or attempts),
        mutation_enabled=bool(mutation_raw.get("enabled", False)),
        mutation_strategies=list(mutation_raw.get("strategies", ["identity"])),
        targets=list(raw.get("targets", [])),
        stages=list(raw.get("stages", ["scan"])),
        budget_max_requests=budget_raw.get("requests"),
        budget_max_tokens=budget_raw.get("tokens"),
        budget_max_cost_usd=budget_raw.get("estimated_cost_usd"),
        budget_max_runtime_minutes=budget_raw.get("max_runtime_minutes"),
        budget_per_suite=dict(budget_raw.get("per_suite", {})),
    )
