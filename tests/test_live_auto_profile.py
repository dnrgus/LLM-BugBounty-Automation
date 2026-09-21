import asyncio

import httpx

from attack_surface.models import AttackSurfaceItem
from live.auto_profile import auto_profile_candidates
from live.classify import ClassifiedCandidate
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore


def _policy() -> PolicyEngine:
    return PolicyEngine(
        {
            "program": "auto-profile-test",
            "scope": {"domains": ["target.example.com"], "url_patterns": ["https://target.example.com/*"]},
            "testing": {"automated_scanning": True},
        }
    )


def _llm_candidate(location: str) -> ClassifiedCandidate:
    item = AttackSurfaceItem(
        source_type="live", asset_type="endpoint", location=location, metadata={"method": "UNKNOWN"}, confidence=0.6
    )
    return ClassifiedCandidate(kind="llm", location=location, confidence=0.8, signals=["api_path"], source_item=item)


def test_auto_profile_finds_a_working_guessed_schema(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"ok": True})
        body = request.read()
        if b'"prompt"' in body:
            return httpx.Response(200, json={"text": "acknowledged"})
        return httpx.Response(400, json={"error": "unrecognized shape"})

    transport = httpx.MockTransport(handler)
    store = SQLiteStore(tmp_path / "auto_profile.sqlite")
    candidates = [_llm_candidate("https://target.example.com/api/chat")]

    results = asyncio.run(auto_profile_candidates(candidates, _policy(), store, transport=transport))

    assert len(results) == 1
    result = results[0]
    assert result.attempted is True
    assert result.error is None
    assert result.profile is not None
    assert result.guessed_schema == {"body": {"prompt": "{{PROMPT}}"}, "response_text_path": "text"}


def test_auto_profile_reports_failure_when_no_guess_matches(tmp_path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    store = SQLiteStore(tmp_path / "auto_profile.sqlite")
    candidates = [_llm_candidate("https://target.example.com/api/chat")]

    results = asyncio.run(auto_profile_candidates(candidates, _policy(), store, transport=transport))

    assert len(results) == 1
    result = results[0]
    assert result.attempted is True
    assert result.profile is None
    assert result.error is not None


def test_auto_profile_handles_root_path_candidate_without_false_scope_rejection(tmp_path) -> None:
    # candidate.location ends in "/" -- CustomHTTPAdapter's own base_url
    # reconstruction must not drop that trailing slash, or the executor's
    # internal scope check would reject a URL already approved above.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"ok": True})
        body = request.read()
        if b'"prompt"' in body:
            return httpx.Response(200, json={"text": "acknowledged"})
        return httpx.Response(400, json={"error": "unrecognized shape"})

    transport = httpx.MockTransport(handler)
    store = SQLiteStore(tmp_path / "auto_profile.sqlite")
    candidates = [_llm_candidate("https://target.example.com/")]

    results = asyncio.run(auto_profile_candidates(candidates, _policy(), store, transport=transport))

    assert len(results) == 1
    result = results[0]
    assert result.attempted is True
    assert result.error is None
    assert result.profile is not None


def test_auto_profile_never_sends_a_request_for_out_of_scope_candidates(tmp_path) -> None:
    requests_seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests_seen.append(request)
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    store = SQLiteStore(tmp_path / "auto_profile.sqlite")
    candidates = [_llm_candidate("https://evil.example.net/api/chat")]

    results = asyncio.run(auto_profile_candidates(candidates, _policy(), store, transport=transport))

    assert len(requests_seen) == 0
    assert len(results) == 1
    assert results[0].attempted is False
    assert "scope" in results[0].error.lower()


def test_auto_profile_skips_non_llm_api_candidates(tmp_path) -> None:
    item = AttackSurfaceItem(source_type="live", asset_type="endpoint", location="https://target.example.com/about")
    web_candidate = ClassifiedCandidate(
        kind="web", location="https://target.example.com/about", confidence=0.5, signals=[], source_item=item
    )
    store = SQLiteStore(tmp_path / "auto_profile.sqlite")

    results = asyncio.run(auto_profile_candidates([web_candidate], _policy(), store, transport=httpx.MockTransport(
        lambda request: httpx.Response(200)
    )))

    assert results == []


def test_auto_profile_skips_relative_locations(tmp_path) -> None:
    candidate = _llm_candidate("/api/chat")
    store = SQLiteStore(tmp_path / "auto_profile.sqlite")

    results = asyncio.run(auto_profile_candidates([candidate], _policy(), store, transport=httpx.MockTransport(
        lambda request: httpx.Response(200)
    )))

    assert results == []
