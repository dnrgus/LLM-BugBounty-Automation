from __future__ import annotations

from dataclasses import dataclass, field

from core.models import CapabilityProfile
from testcase.schema import Testcase


@dataclass(frozen=True)
class CoverageEntry:
    framework: str
    tag: str
    testcase_ids: list[str] = field(default_factory=list)
    executable_testcase_ids: list[str] = field(default_factory=list)
    executed_testcase_ids: list[str] = field(default_factory=list)

    @property
    def has_defined_tests(self) -> bool:
        return bool(self.testcase_ids)

    @property
    def is_executable(self) -> bool:
        return bool(self.executable_testcase_ids)

    @property
    def is_executed(self) -> bool:
        return bool(self.executed_testcase_ids)

    def to_dict(self) -> dict[str, object]:
        return {
            "framework": self.framework,
            "tag": self.tag,
            "testcase_ids": self.testcase_ids,
            "executable_testcase_ids": self.executable_testcase_ids,
            "executed_testcase_ids": self.executed_testcase_ids,
            "defined": self.has_defined_tests,
            "executable": self.is_executable,
            "executed": self.is_executed,
        }


def build_coverage_matrix(
    testcases: list[Testcase],
    capabilities: CapabilityProfile,
    executed_testcase_ids: set[str] | None = None,
) -> list[CoverageEntry]:
    executed = executed_testcase_ids or set()
    matrix: dict[tuple[str, str], dict[str, list[str]]] = {}
    for case in testcases:
        executable = capabilities.supports(case.requires)
        for framework, tags in case.frameworks.items():
            for tag in tags:
                key = (framework, tag)
                row = matrix.setdefault(
                    key,
                    {"testcase_ids": [], "executable_testcase_ids": [], "executed_testcase_ids": []},
                )
                row["testcase_ids"].append(case.id)
                if executable:
                    row["executable_testcase_ids"].append(case.id)
                if executable and case.id in executed:
                    row["executed_testcase_ids"].append(case.id)
    return [
        CoverageEntry(
            framework=framework,
            tag=tag,
            testcase_ids=sorted(values["testcase_ids"]),
            executable_testcase_ids=sorted(values["executable_testcase_ids"]),
            executed_testcase_ids=sorted(values["executed_testcase_ids"]),
        )
        for (framework, tag), values in sorted(matrix.items())
    ]


def coverage_summary(matrix: list[CoverageEntry]) -> dict[str, int]:
    return {
        "defined": sum(1 for entry in matrix if entry.has_defined_tests),
        "executable": sum(1 for entry in matrix if entry.is_executable),
        "executed": sum(1 for entry in matrix if entry.is_executed),
    }
