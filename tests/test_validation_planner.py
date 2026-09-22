"""P3.3-2 Validation Plan Generator (roadmap v3.3.0 Static -> Dynamic Validation)."""

from attack_surface.models import AttackSurfaceItem
from correlation.resolver import resolve_entities
from validation.planner import generate_validation_plans, load_templates


def _endpoint(location: str, handler: str | None = None, method: str = "GET") -> AttackSurfaceItem:
    metadata = {"method": method, "file": "app.py"}
    if handler:
        metadata["handler"] = handler
    return AttackSurfaceItem(source_type="source", asset_type="endpoint", location=location, metadata=metadata)


def _live(url: str) -> AttackSurfaceItem:
    return AttackSurfaceItem(source_type="live", asset_type="endpoint", location=url, metadata={"method": "GET"})


def _dataflow(sink_type: str) -> AttackSurfaceItem:
    return AttackSurfaceItem(source_type="source", asset_type="dataflow", location="app.py:1", metadata={"sink_type": sink_type})


def _auth(handler: str, detected: bool) -> AttackSurfaceItem:
    return AttackSurfaceItem(
        source_type="source", asset_type="auth", location="app.py:1", metadata={"handler": handler, "detected": detected}
    )


def _ai(kind: str, file: str = "app.py") -> AttackSurfaceItem:
    return AttackSurfaceItem(source_type="source", asset_type=kind, location=file, metadata={"file": file})


def test_load_templates_reads_the_real_categories_file() -> None:
    templates = load_templates()
    assert "endpoint" in templates
    assert "llm" in templates
    assert templates["llm"]["executor"] == "testcase_suite:llm_core"


def test_endpoint_with_no_live_match_is_unsupported() -> None:
    plan = generate_validation_plans([_endpoint("/api/chat")])[0]
    assert plan.classification == "unsupported"
    assert "no corresponding live endpoint" in plan.reason


def test_endpoint_with_low_confidence_match_is_review_only() -> None:
    source = _endpoint("/api/chat")
    live = _live("https://target.example.com/gateway/api/chat")  # proxy-prefix match -> review_required
    matches = resolve_entities([source], [live])
    plan = generate_validation_plans([source, live], matches=matches)[0]
    assert plan.classification == "review_only"
    assert "confidence too low" in plan.reason


def test_endpoint_with_good_match_and_no_auth_guard_is_executable() -> None:
    source = _endpoint("/api/chat", handler="chat")
    live = _live("https://target.example.com/api/chat")
    matches = resolve_entities([source], [live])
    plans = generate_validation_plans([source, live], matches=matches)
    endpoint_plan = next(plan for plan in plans if plan.candidate_id == source.id)
    assert endpoint_plan.classification == "executable"
    assert endpoint_plan.control_test is not None
    assert endpoint_plan.success_criteria is not None


def test_endpoint_with_detected_auth_guard_and_no_auth_context_is_review_only() -> None:
    source = _endpoint("/api/admin", handler="admin")
    live = _live("https://target.example.com/api/admin")
    auth_item = _auth("admin", detected=True)
    matches = resolve_entities([source], [live])

    plan_no_context = generate_validation_plans([source, live, auth_item], matches=matches, auth_context_available=False)
    endpoint_plan_no_context = next(p for p in plan_no_context if p.candidate_id == source.id)
    assert endpoint_plan_no_context.classification == "review_only"
    assert "authenticated_session" in endpoint_plan_no_context.required_context

    plan_with_context = generate_validation_plans([source, live, auth_item], matches=matches, auth_context_available=True)
    endpoint_plan_with_context = next(p for p in plan_with_context if p.candidate_id == source.id)
    assert endpoint_plan_with_context.classification == "executable"


def test_destructive_dataflow_sink_requires_approval_and_is_never_executable() -> None:
    for sink_type in ("os_command", "deserialization", "code_execution", "file_access", "template_injection"):
        plan = generate_validation_plans([_dataflow(sink_type)])[0]
        assert plan.classification == "review_only"
        assert plan.requires_approval is True
        assert "destructive" in plan.reason


def test_non_destructive_dataflow_sink_is_review_only_without_approval() -> None:
    plan = generate_validation_plans([_dataflow("sql_injection")])[0]
    assert plan.classification == "review_only"
    assert plan.requires_approval is False


def test_prompt_injection_sink_dataflow_defers_to_the_llm_capability_hint() -> None:
    plan = generate_validation_plans([_dataflow("prompt_injection_sink")])[0]
    assert plan.classification == "review_only"
    assert plan.requires_approval is False
    assert "llm" in plan.reason


def test_auth_candidate_is_always_review_only_regardless_of_detected() -> None:
    detected_plan = generate_validation_plans([_auth("h", detected=True)])[0]
    missing_plan = generate_validation_plans([_auth("h", detected=False)])[0]
    assert detected_plan.classification == "review_only"
    assert missing_plan.classification == "review_only"
    assert detected_plan.reason != missing_plan.reason


def test_secret_is_unsupported() -> None:
    secret_item = AttackSurfaceItem(source_type="source", asset_type="secret", location="app.py:1", metadata={})
    plan = generate_validation_plans([secret_item])[0]
    assert plan.classification == "unsupported"


def test_plain_function_and_parameter_signals_are_unsupported() -> None:
    function_item = AttackSurfaceItem(source_type="source", asset_type="function", location="app.py:1", metadata={})
    parameter_item = AttackSurfaceItem(source_type="source", asset_type="parameter", location="app.py:1", metadata={})
    plans = generate_validation_plans([function_item, parameter_item])
    assert all(plan.classification == "unsupported" for plan in plans)


def test_llm_capability_hint_becomes_executable_via_a_same_file_live_matched_endpoint() -> None:
    source = _endpoint("/api/chat", handler="chat")
    live = _live("https://target.example.com/api/chat")
    llm_hint = _ai("llm")
    matches = resolve_entities([source], [live])

    plans = generate_validation_plans([source, live, llm_hint], matches=matches)
    llm_plan = next(p for p in plans if p.candidate_id == llm_hint.id)
    assert llm_plan.classification == "executable"
    assert "testcase_suite:llm_core" in llm_plan.reason


def test_llm_capability_hint_without_a_live_match_is_review_only() -> None:
    llm_hint = _ai("llm")
    plan = generate_validation_plans([llm_hint])[0]
    assert plan.classification == "review_only"
    assert "live_endpoint_correlation" in plan.required_context


def test_validation_plan_to_dict_is_json_serializable() -> None:
    import json

    plans = generate_validation_plans([_dataflow("os_command"), _auth("h", True)])
    json.dumps([plan.to_dict() for plan in plans])
