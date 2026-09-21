from __future__ import annotations

from pathlib import Path

import yaml

from scenario.models import Scenario, ScenarioStep


def load_scenarios(path: Path | str) -> list[Scenario]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    raw_scenarios = data.get("scenarios", data if isinstance(data, list) else [])
    scenarios = []
    for raw in raw_scenarios:
        steps = [ScenarioStep(**step) for step in raw.get("steps", [])]
        scenarios.append(Scenario(id=raw["id"], name=raw.get("name", raw["id"]), steps=steps, description=raw.get("description", "")))

    seen: set[str] = set()
    for scenario in scenarios:
        if not scenario.steps:
            raise ValueError(f"scenario {scenario.id} has no steps")
        if scenario.id in seen:
            raise ValueError(f"duplicate scenario id: {scenario.id}")
        seen.add(scenario.id)
    return scenarios
