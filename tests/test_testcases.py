from testcase.loader import load_testcases
from targets.fake import FakeLLMTarget


def test_load_testcases() -> None:
    cases = load_testcases("testcase/suites/basic.yaml")
    assert [case.id for case in cases] == ["LLM-PI-001", "LLM-SP-001"]
    assert cases[0].content_hash


async def _capabilities() -> list[str]:
    target = FakeLLMTarget()
    profile = await target.capabilities()
    cases = load_testcases("testcase/suites/basic.yaml")
    return [case.id for case in cases if profile.supports(case.requires)]


def test_capability_selection() -> None:
    import asyncio

    assert asyncio.run(_capabilities()) == ["LLM-PI-001", "LLM-SP-001"]

