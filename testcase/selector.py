from __future__ import annotations

from core.models import CapabilityProfile
from scope.policy import PolicyEngine
from testcase.schema import Testcase


def select_executable_testcases(
    testcases: list[Testcase],
    capabilities: CapabilityProfile,
    policy: PolicyEngine | None = None,
) -> list[Testcase]:
    selected: list[Testcase] = []
    for case in testcases:
        if not capabilities.supports(case.requires):
            continue
        if policy is not None and not policy.validate_testcase(case.category).allowed:
            continue
        selected.append(case)
    return selected
