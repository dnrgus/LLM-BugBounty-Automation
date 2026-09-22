"""P3.3-1 Static/Live Entity Resolver (roadmap v3.3.0 Static -> Dynamic Validation)."""

from attack_surface.models import AttackSurfaceItem
from correlation.resolver import canonicalize_path, resolve_entities, strip_version_prefix


def _source(path: str, method: str = "GET") -> AttackSurfaceItem:
    return AttackSurfaceItem(
        source_type="source", asset_type="endpoint", location=path,
        metadata={"method": method, "file": "app.py", "line": 1},
    )


def _live(url: str, method: str = "GET") -> AttackSurfaceItem:
    return AttackSurfaceItem(source_type="live", asset_type="endpoint", location=url, metadata={"method": method})


def test_canonicalize_path_strips_trailing_slash() -> None:
    assert canonicalize_path("/api/chat/") == "/api/chat"
    assert canonicalize_path("/") == "/"


def test_canonicalize_path_collapses_every_template_syntax_to_one_token() -> None:
    assert canonicalize_path("/api/users/<int:id>") == "/api/users/{param}"
    assert canonicalize_path("/api/users/<id>") == "/api/users/{param}"
    assert canonicalize_path("/api/users/{id}") == "/api/users/{param}"
    assert canonicalize_path("/api/users/:id") == "/api/users/{param}"
    assert canonicalize_path("/api/files/*slug") == "/api/files/{param}"


def test_canonicalize_path_collapses_concrete_id_like_segments() -> None:
    assert canonicalize_path("/api/users/12345") == "/api/users/{param}"
    assert canonicalize_path("/api/users/550e8400-e29b-41d4-a716-446655440000") == "/api/users/{param}"
    assert canonicalize_path("/api/posts/about") == "/api/posts/about"  # not id-shaped, left alone


def test_strip_version_prefix() -> None:
    assert strip_version_prefix("/v1/api/chat") == "/api/chat"
    assert strip_version_prefix("/v2.1/api/chat") == "/api/chat"
    assert strip_version_prefix("/api/chat") == "/api/chat"


def test_known_mapping_corpus_resolves_templated_source_route_to_concrete_live_url() -> None:
    source = _source("/api/users/<int:id>")
    live = _live("https://target.example.com/api/users/42")
    matches = resolve_entities([source], [live])
    assert len(matches) == 1
    match = matches[0]
    assert match.confidence == 0.8
    assert "canonicalized_path_match" in match.basis
    assert match.review_required is False


def test_exact_match_gets_the_highest_confidence() -> None:
    source = _source("/api/chat")
    live = _live("https://target.example.com/api/chat")
    match = resolve_entities([source], [live])[0]
    assert match.confidence == 0.9
    assert match.basis == ["exact_path"]


def test_source_non_get_method_lowers_confidence_with_an_explicit_caveat() -> None:
    source = _source("/api/chat", method="POST")
    live = _live("https://target.example.com/api/chat")  # discovery only ever probes via GET
    match = resolve_entities([source], [live])[0]
    assert match.confidence == 0.7  # 0.9 - 0.2
    assert "source_declares_non_get_method_live_only_probed_via_get" in match.basis


def test_version_prefix_fixture_matches_tolerantly_at_reduced_confidence() -> None:
    source = _source("/v1/api/chat")
    live = _live("https://target.example.com/api/chat")
    match = resolve_entities([source], [live])[0]
    assert match.basis == ["version_prefix_tolerant_match"]
    assert match.confidence == 0.65
    assert match.review_required is False


def test_proxy_prefix_fixture_matches_but_requires_review() -> None:
    source = _source("/api/chat")
    live = _live("https://target.example.com/gateway/api/chat")
    match = resolve_entities([source], [live])[0]
    assert match.basis == ["proxy_prefix_suffix_match"]
    assert match.confidence == 0.5
    assert match.review_required is True


def test_trailing_slash_regression_still_matches() -> None:
    source = _source("/api/chat")
    live = _live("https://target.example.com/api/chat/")
    matches = resolve_entities([source], [live])
    assert len(matches) == 1
    assert matches[0].confidence == 0.8  # not a literal string match once trailing-slash differs


def test_unrelated_paths_produce_no_match() -> None:
    source = _source("/api/other")
    live = _live("https://target.example.com/api/chat")
    assert resolve_entities([source], [live]) == []


def test_non_endpoint_items_are_ignored() -> None:
    param_item = AttackSurfaceItem(source_type="source", asset_type="parameter", location="x", metadata={})
    live = _live("https://target.example.com/api/chat")
    assert resolve_entities([param_item], [live]) == []
    assert resolve_entities([_source("/api/chat")], [param_item]) == []


def test_entity_match_to_dict_is_json_serializable() -> None:
    import json

    source = _source("/api/chat")
    live = _live("https://target.example.com/api/chat")
    match = resolve_entities([source], [live])[0]
    json.dumps(match.to_dict())
