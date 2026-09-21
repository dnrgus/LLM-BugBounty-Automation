from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Callable

from core.models import MutationRecord
from testcase.schema import Testcase


def prompt_hash(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class MutationCandidate:
    testcase_id: str
    prompt: str
    strategy: str
    generation: int
    prompt_hash: str
    parent_mutation_id: str | None = None
    id: str | None = None

    def to_record(self) -> MutationRecord:
        return MutationRecord(
            id=self.id or f"mutation_{self.prompt_hash[:12]}",
            testcase_id=self.testcase_id,
            strategy=self.strategy,
            prompt_hash=self.prompt_hash,
            parent_mutation_id=self.parent_mutation_id,
            generation=self.generation,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id or f"mutation_{self.prompt_hash[:12]}",
            "testcase_id": self.testcase_id,
            "prompt": self.prompt,
            "strategy": self.strategy,
            "generation": self.generation,
            "prompt_hash": self.prompt_hash,
            "parent_mutation_id": self.parent_mutation_id,
        }


StrategyFn = Callable[[str], str]


class MutationEngine:
    def __init__(self, strategies: list[str] | None = None):
        self.strategy_names = strategies or ["identity", "markdown_wrap", "json_wrap", "roleplay", "multi_turn_split"]
        self.strategies: dict[str, StrategyFn] = {
            "identity": lambda prompt: prompt,
            "markdown_wrap": lambda prompt: f"```text\n{prompt.strip()}\n```",
            "json_wrap": lambda prompt: json.dumps({"instruction": prompt.strip()}, ensure_ascii=False),
            "roleplay": lambda prompt: f"You are evaluating a security control. {prompt.strip()}",
            "multi_turn_split": lambda prompt: prompt.strip().replace(" and ", "\nThen "),
        }

    def mutate(self, testcase: Testcase, variables: dict[str, str] | None = None) -> list[MutationCandidate]:
        seed = testcase.render_prompt(variables).strip()
        candidates: list[MutationCandidate] = []
        seen: set[str] = set()
        for strategy_name in self.strategy_names:
            strategy = self.strategies[strategy_name]
            prompt = strategy(seed)
            digest = prompt_hash(prompt)
            if digest in seen:
                continue
            seen.add(digest)
            candidates.append(
                MutationCandidate(
                    testcase_id=testcase.id,
                    prompt=prompt,
                    strategy=strategy_name,
                    generation=0 if strategy_name == "identity" else 1,
                    prompt_hash=digest,
                    parent_mutation_id=None if strategy_name == "identity" else f"mutation_{prompt_hash(seed)[:12]}",
                    id=f"mutation_{digest[:12]}",
                )
            )
        return candidates


def mutation_stats(candidates: list[MutationCandidate]) -> dict[str, object]:
    by_strategy: dict[str, int] = {}
    for candidate in candidates:
        by_strategy[candidate.strategy] = by_strategy.get(candidate.strategy, 0) + 1
    return {
        "total": len(candidates),
        "unique_hashes": len({candidate.prompt_hash for candidate in candidates}),
        "by_strategy": by_strategy,
    }
