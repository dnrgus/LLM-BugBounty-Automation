from attack_surface.merge import merge_items
from attack_surface.models import AttackSurfaceItem


def test_attack_surface_item_to_dict_round_trips_fields() -> None:
    item = AttackSurfaceItem(
        source_type="live",
        asset_type="endpoint",
        location="/api/chat",
        metadata={"method": "POST"},
        confidence=0.8,
        evidence_refs=["LIVE-1"],
        correlation_keys=["POST:/api/chat"],
    )
    payload = item.to_dict()
    assert payload["source_type"] == "live"
    assert payload["asset_type"] == "endpoint"
    assert payload["location"] == "/api/chat"
    assert payload["confidence"] == 0.8
    assert payload["id"].startswith("AS_")


def test_merge_items_leaves_unrelated_endpoints_separate() -> None:
    items = [
        AttackSurfaceItem(source_type="live", asset_type="endpoint", location="/api/chat", metadata={"method": "POST"}),
        AttackSurfaceItem(source_type="live", asset_type="endpoint", location="/api/status", metadata={"method": "GET"}),
    ]
    merged = merge_items(items)
    assert len(merged) == 2
    assert {item.location for item in merged} == {"/api/chat", "/api/status"}


def test_merge_items_combines_matching_endpoint_and_boosts_confidence() -> None:
    static_item = AttackSurfaceItem(
        source_type="source",
        asset_type="endpoint",
        location="https://target.example.com/api/chat",
        metadata={"method": "POST", "framework": "fastapi"},
        confidence=0.6,
        evidence_refs=["SRC-22"],
    )
    live_item = AttackSurfaceItem(
        source_type="live",
        asset_type="endpoint",
        location="https://target.example.com/api/chat",
        metadata={"method": "POST", "status_code": 200},
        confidence=0.7,
        evidence_refs=["LIVE-81"],
    )
    merged = merge_items([static_item, live_item])
    assert len(merged) == 1
    result = merged[0]
    assert result.source_type == "merged"
    assert result.confidence > max(static_item.confidence, live_item.confidence)
    assert set(result.evidence_refs) == {"SRC-22", "LIVE-81"}
    assert len(result.provenance) == 2
    # both original metadata dicts are preserved, not overwritten
    assert result.metadata["framework"] == "fastapi"
    assert result.metadata["status_code"] == 200


def test_merge_items_combines_matching_parameter() -> None:
    items = [
        AttackSurfaceItem(
            source_type="source", asset_type="parameter", location="app/routes/profile.py:41",
            metadata={"name": "id", "position": "query"},
        ),
        AttackSurfaceItem(
            source_type="live", asset_type="parameter", location="https://target.example.com/api/profile",
            metadata={"name": "id", "position": "query"},
        ),
    ]
    merged = merge_items(items)
    assert len(merged) == 1
    assert merged[0].source_type == "merged"


def test_merge_items_boosts_confidence_further_when_llm_sdk_matches_live_ai_endpoint() -> None:
    static_item = AttackSurfaceItem(
        source_type="source", asset_type="endpoint", location="/api/chat",
        metadata={"method": "POST", "llm_detected": True}, confidence=0.5,
    )
    live_item = AttackSurfaceItem(
        source_type="live", asset_type="endpoint", location="/api/chat",
        metadata={"method": "POST", "llm_detected": True}, confidence=0.5,
    )
    plain_static = AttackSurfaceItem(
        source_type="source", asset_type="endpoint", location="/api/status",
        metadata={"method": "GET", "llm_detected": True}, confidence=0.5,
    )
    plain_live = AttackSurfaceItem(
        source_type="live", asset_type="endpoint", location="/api/other",
        metadata={"method": "GET"}, confidence=0.5,
    )

    with_llm_match = merge_items([static_item, live_item])[0]
    without_llm_match = merge_items([plain_static])[0]
    assert with_llm_match.confidence > 0.5 + 0.15  # static+dynamic boost alone would only reach this
    assert without_llm_match.confidence == 0.5
    assert plain_live.metadata.get("llm_detected") is None


def test_merge_items_preserves_conflicting_metadata_only_via_provenance() -> None:
    item_a = AttackSurfaceItem(
        source_type="source", asset_type="endpoint", location="/api/chat",
        metadata={"method": "POST", "auth": "none"},
    )
    item_b = AttackSurfaceItem(
        source_type="live", asset_type="endpoint", location="/api/chat",
        metadata={"method": "POST", "auth": "bearer"},
    )
    merged = merge_items([item_a, item_b])[0]
    # conflicting "auth" value is dropped from the merged view (never silently
    # overwritten) but both originals are still recoverable from provenance
    assert "auth" not in merged.metadata
    provenance_auth_values = {entry["metadata"]["auth"] for entry in merged.provenance}
    assert provenance_auth_values == {"none", "bearer"}
