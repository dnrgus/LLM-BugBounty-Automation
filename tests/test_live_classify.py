from attack_surface.models import AttackSurfaceItem
from live.classify import classify_items


def _endpoint(location: str, method: str = "GET") -> AttackSurfaceItem:
    return AttackSurfaceItem(
        source_type="live", asset_type="endpoint", location=location, metadata={"method": method}, confidence=0.6
    )


def test_classify_plain_page_as_web() -> None:
    items = [_endpoint("https://target.example.com/about")]
    candidates = classify_items(items)
    assert [c.kind for c in candidates] == ["web"]


def test_classify_api_path_as_api() -> None:
    items = [_endpoint("https://target.example.com/api/orders")]
    candidates = classify_items(items)
    assert [c.kind for c in candidates] == ["api"]


def test_classify_api_path_with_chat_keyword_as_llm_and_api() -> None:
    items = [_endpoint("https://target.example.com/api/chat", method="UNKNOWN")]
    candidates = classify_items(items)
    kinds = {c.kind for c in candidates}
    assert kinds == {"llm", "api"}
    llm_candidate = next(c for c in candidates if c.kind == "llm")
    assert llm_candidate.confidence > 0.6


def test_classify_graphql_path() -> None:
    items = [_endpoint("https://target.example.com/graphql")]
    candidates = classify_items(items)
    assert [c.kind for c in candidates] == ["graphql"]


def test_classify_websocket_url() -> None:
    items = [
        AttackSurfaceItem(
            source_type="live", asset_type="websocket", location="wss://target.example.com/ws/chat", confidence=0.5
        )
    ]
    candidates = classify_items(items)
    kinds = {c.kind for c in candidates}
    assert kinds == {"websocket", "llm"}


def test_classify_websocket_url_without_chat_hint_is_only_websocket() -> None:
    items = [
        AttackSurfaceItem(
            source_type="live", asset_type="websocket", location="wss://target.example.com/updates", confidence=0.5
        )
    ]
    candidates = classify_items(items)
    assert [c.kind for c in candidates] == ["websocket"]


def test_classify_llm_hint_item_with_rag_keyword() -> None:
    items = [
        AttackSurfaceItem(
            source_type="live",
            asset_type="llm",
            location="https://target.example.com/",
            metadata={"hints": ["chat", "retrieval"]},
            confidence=0.35,
        )
    ]
    candidates = classify_items(items)
    kinds = {c.kind for c in candidates}
    assert kinds == {"rag", "llm"}


def test_classify_llm_hint_item_with_agent_keyword() -> None:
    items = [
        AttackSurfaceItem(
            source_type="live",
            asset_type="llm",
            location="https://target.example.com/",
            metadata={"hints": ["agent", "copilot"]},
            confidence=0.35,
        )
    ]
    candidates = classify_items(items)
    kinds = {c.kind for c in candidates}
    assert kinds == {"agent", "llm"}


def test_classify_ignores_non_capability_asset_types() -> None:
    items = [
        AttackSurfaceItem(source_type="live", asset_type="secret", location="https://target.example.com/app.js.map"),
        AttackSurfaceItem(source_type="live", asset_type="auth", location="https://target.example.com/"),
    ]
    assert classify_items(items) == []


def test_classify_candidate_to_dict_is_json_serializable() -> None:
    import json

    items = [_endpoint("https://target.example.com/about")]
    candidate = classify_items(items)[0]
    payload = candidate.to_dict()
    json.dumps(payload)
    assert payload["kind"] == "web"
    assert payload["location"] == "https://target.example.com/about"
