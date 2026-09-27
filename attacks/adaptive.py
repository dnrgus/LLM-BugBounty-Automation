from __future__ import annotations

from dataclasses import dataclass

from tools.adapters.base import NormalizedResult
from attacks.mutation import MutationCandidate, MutationEngine
from testcase.schema import Testcase


@dataclass(frozen=True)
class AdaptivePlan:
    testcase_id: str
    seed_title: str
    mutations: list[MutationCandidate]

    def to_dict(self) -> dict[str, object]:
        return {
            "testcase_id": self.testcase_id,
            "seed_title": self.seed_title,
            "mutations": [mutation.to_dict() for mutation in self.mutations],
        }


class AdaptivePlanner:
    def __init__(self, mutation_engine: MutationEngine | None = None):
        self.mutation_engine = mutation_engine or MutationEngine(strategies=["roleplay", "json_wrap", "multi_turn_split"])

    def plan_from_result(self, result: NormalizedResult, testcase: Testcase) -> AdaptivePlan:
        mutations = self.mutation_engine.mutate(testcase)
        return AdaptivePlan(
            testcase_id=testcase.id,
            seed_title=result.title,
            mutations=mutations,
        )
