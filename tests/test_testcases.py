from testcase.loader import load_testcases
from testcase.coverage import build_coverage_matrix, coverage_summary
from testcase.selector import select_executable_testcases
from targets.fake import FakeLLMTarget
from targets.fake import FakeAgentTarget, FakeRAGTarget
from scope.policy import PolicyEngine


def test_load_testcases() -> None:
    cases = load_testcases("testcase/suites/basic.yaml")
    assert [case.id for case in cases] == [
        "LLM-PI-001",
        "LLM-SP-001",
        "LLM-TOOL-001",
        "LLM-RAG-001",
        "LLM-RAG-002",
    ]
    assert cases[0].content_hash
    assert cases[2].render_prompt({"RESOURCE": "admin console"}).strip().endswith("admin console without approval.")


async def _capabilities() -> list[str]:
    target = FakeLLMTarget()
    profile = await target.capabilities()
    cases = load_testcases("testcase/suites/basic.yaml")
    return [case.id for case in select_executable_testcases(cases, profile)]


def test_capability_selection() -> None:
    import asyncio

    assert asyncio.run(_capabilities()) == ["LLM-PI-001", "LLM-SP-001"]


async def _agent_policy_selection() -> list[str]:
    target = FakeAgentTarget()
    profile = await target.capabilities()
    cases = load_testcases("testcase/suites/basic.yaml")
    policy = PolicyEngine.from_yaml("config/scope.example.yaml")
    return [case.id for case in select_executable_testcases(cases, profile, policy)]


def test_policy_removes_denied_tool_suite() -> None:
    import asyncio

    assert asyncio.run(_agent_policy_selection()) == ["LLM-PI-001", "LLM-SP-001"]


async def _rag_coverage_summary() -> dict[str, int]:
    target = FakeRAGTarget()
    profile = await target.capabilities()
    cases = load_testcases("testcase/suites/basic.yaml")
    matrix = build_coverage_matrix(cases, profile, {"LLM-RAG-001"})
    return coverage_summary(matrix)


def test_coverage_distinguishes_defined_executable_and_executed() -> None:
    import asyncio

    summary = asyncio.run(_rag_coverage_summary())
    assert summary["defined"] == 8
    assert summary["executable"] == 6
    assert summary["executed"] == 2
