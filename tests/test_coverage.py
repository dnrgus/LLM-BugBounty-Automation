import pytest

from core.models import CapabilityProfile
from testcase.coverage import build_coverage_matrix
from testcase.loader import load_testcases
from testcase.schema import Testcase


def test_coverage_entry_tracks_framework_tags() -> None:
    cases = load_testcases("testcase/suites/basic.yaml")
    matrix = build_coverage_matrix(cases, CapabilityProfile(chat=True), {"LLM-PI-001"})
    row = next(entry for entry in matrix if entry.framework == "owasp_llm_2026" and entry.tag == "LLM01")
    assert row.testcase_ids == ["LLM-PI-001"]
    assert row.executable_testcase_ids == ["LLM-PI-001"]
    assert row.executed_testcase_ids == ["LLM-PI-001"]


def test_testcase_validation_rejects_unknown_session_strategy() -> None:
    case = Testcase(
        id="BROKEN",
        name="Broken",
        category="prompt_injection",
        requires=["chat"],
        prompt="hello",
        judges=["rule"],
        session_strategy="not_a_real_strategy",
    )
    with pytest.raises(ValueError, match="session_strategy"):
        case.validate()


def test_testcase_validation_requires_judges() -> None:
    case = Testcase(
        id="BROKEN",
        name="Broken",
        category="prompt_injection",
        requires=["chat"],
        prompt="hello",
        judges=[],
    )
    with pytest.raises(ValueError, match="judge"):
        case.validate()
