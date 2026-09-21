from core.budget import AttackBudget


def test_budget_allows_requests_under_the_cap() -> None:
    budget = AttackBudget(max_requests=2)
    assert budget.check().allowed
    budget.commit_usage()
    assert budget.check().allowed
    budget.commit_usage()
    decision = budget.check()
    assert not decision.allowed
    assert decision.reason == "budget_exhausted:requests"


def test_budget_stops_on_token_cap() -> None:
    budget = AttackBudget(max_tokens=100)
    budget.commit_usage(tokens=90)
    assert budget.check().allowed
    budget.commit_usage(tokens=20)
    decision = budget.check()
    assert not decision.allowed
    assert decision.reason == "budget_exhausted:tokens"


def test_budget_stops_on_cost_cap() -> None:
    budget = AttackBudget(max_cost_usd=1.0)
    budget.commit_usage(cost_usd=0.5)
    assert budget.check().allowed
    budget.commit_usage(cost_usd=0.6)
    decision = budget.check()
    assert not decision.allowed
    assert decision.reason == "budget_exhausted:cost"


def test_budget_enforces_per_suite_caps_independently_of_total() -> None:
    budget = AttackBudget(max_requests=100, per_suite_requests={"prompt_injection": 1})
    assert budget.check(category="prompt_injection").allowed
    budget.commit_usage(category="prompt_injection")
    decision = budget.check(category="prompt_injection")
    assert not decision.allowed
    assert decision.reason == "budget_exhausted:suite:prompt_injection"
    # a different suite is unaffected
    assert budget.check(category="rag").allowed


def test_budget_with_no_limits_never_stops() -> None:
    budget = AttackBudget()
    for _ in range(50):
        assert budget.check().allowed
        budget.commit_usage(tokens=10_000, cost_usd=5.0)


def test_budget_once_stopped_stays_stopped() -> None:
    budget = AttackBudget(max_requests=1)
    budget.commit_usage()
    first = budget.check()
    assert not first.allowed
    # even if usage were hypothetically reset elsewhere, stop_reason is sticky
    budget.requests_used = 0
    second = budget.check()
    assert not second.allowed
    assert second.reason == first.reason


def test_budget_usage_snapshot_reports_current_counters() -> None:
    budget = AttackBudget(max_requests=10)
    budget.commit_usage(category="rag", tokens=42, cost_usd=0.1)
    usage = budget.usage
    assert usage["requests_used"] == 1
    assert usage["tokens_used"] == 42
    assert usage["cost_used_usd"] == 0.1
    assert usage["per_suite_used"] == {"rag": 1}
    assert usage["stop_reason"] is None
