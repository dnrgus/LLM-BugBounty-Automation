from core.budget import AttackBudget
from packs.registry import AttackPack
from packs.selector import select_packs
from scope.policy import PolicyEngine


def _policy(**testing_overrides) -> PolicyEngine:
    testing = {
        "automated_scanning": True,
        "prompt_injection": True,
        "system_prompt_leak": True,
        "indirect_injection": True,
        "rag_security": True,
        "tool_abuse": False,
    }
    testing.update(testing_overrides)
    return PolicyEngine(
        {
            "program": "pack-selector-test",
            "scope": {"domains": ["target.example.com"], "url_patterns": ["https://target.example.com/*"]},
            "testing": testing,
        }
    )


def test_select_packs_matches_applicable_kind() -> None:
    selections = select_packs({"llm"}, _policy())
    by_id = {s.pack.id: s for s in selections}
    assert by_id["llm_core"].selected is True
    assert by_id["web_scan"].selected is False
    assert "does not apply" in by_id["web_scan"].reason


def test_select_packs_every_registered_pack_gets_a_decision() -> None:
    from packs.registry import DEFAULT_PACKS

    selections = select_packs({"llm"}, _policy())
    assert {s.pack.id for s in selections} == {p.id for p in DEFAULT_PACKS}


def test_select_packs_denied_by_policy_testing_category() -> None:
    selections = select_packs({"agent"}, _policy(tool_abuse=False))
    by_id = {s.pack.id: s for s in selections}
    assert by_id["agent_tool_abuse"].selected is False
    assert "policy denies" in by_id["agent_tool_abuse"].reason
    assert "tool_abuse" in by_id["agent_tool_abuse"].reason


def test_select_packs_allowed_when_policy_permits() -> None:
    selections = select_packs({"agent"}, _policy(tool_abuse=True))
    by_id = {s.pack.id: s for s in selections}
    assert by_id["agent_tool_abuse"].selected is True


def test_select_packs_rejects_when_budget_insufficient() -> None:
    budget = AttackBudget(max_requests=5)
    selections = select_packs({"llm"}, _policy(), budget=budget)
    by_id = {s.pack.id: s for s in selections}
    assert by_id["llm_core"].selected is False
    assert "insufficient budget" in by_id["llm_core"].reason


def test_select_packs_allows_when_budget_sufficient() -> None:
    budget = AttackBudget(max_requests=1000)
    selections = select_packs({"llm"}, _policy(), budget=budget)
    by_id = {s.pack.id: s for s in selections}
    assert by_id["llm_core"].selected is True


def test_select_packs_unbounded_budget_never_blocks() -> None:
    budget = AttackBudget()  # max_requests=None -- unbounded
    selections = select_packs({"llm"}, _policy(), budget=budget)
    by_id = {s.pack.id: s for s in selections}
    assert by_id["llm_core"].selected is True


def test_select_packs_a_target_with_multiple_kinds_selects_multiple_packs() -> None:
    selections = select_packs({"llm", "api"}, _policy())
    selected_ids = {s.pack.id for s in selections if s.selected}
    assert "llm_core" in selected_ids
    assert "api_fuzz" in selected_ids
    assert "secret_scan" in selected_ids  # applies to both llm and api


def test_pack_selection_to_dict_is_json_serializable() -> None:
    import json

    selections = select_packs({"llm"}, _policy())
    payload = [s.to_dict() for s in selections]
    json.dumps(payload)
    llm_core = next(p for p in payload if p["pack_id"] == "llm_core")
    assert llm_core["selected"] is True
    assert llm_core["tool_ids"] == ["testcase_suite"]


def test_select_packs_with_custom_pack_list() -> None:
    custom_pack = AttackPack(
        id="custom_test",
        name="Custom Test Pack",
        applies_to=("web",),
        testing_categories=("automated_scanning",),
        estimated_request_cost=1,
    )
    selections = select_packs({"web"}, _policy(), packs=(custom_pack,))
    assert len(selections) == 1
    assert selections[0].pack.id == "custom_test"
    assert selections[0].selected is True
