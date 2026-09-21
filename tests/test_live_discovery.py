import asyncio

import httpx

from live.discovery import discover_target
from scope.policy import PolicyEngine

_HTML = """
<html>
<head><title>Test Target</title></head>
<body>
  <form action="/login">
    <input type="password" name="pw">
  </form>
  <a href="https://ai.example.com/about">About</a>
  <a href="https://evil.example.net/out-of-scope">External</a>
  <script src="https://ai.example.com/app.js"></script>
  This is an AI chat assistant that can generate responses using retrieval.
</body>
</html>
"""

_ABOUT_HTML = "<html><head><title>About</title></head><body>no links here</body></html>"

_JS = """
fetch("/api/chat");
const ws = new WebSocket("wss://ai.example.com/ws/stream");
//# sourceMappingURL=app.js.map
"""


def _policy() -> PolicyEngine:
    return PolicyEngine(
        {
            "program": "discovery-test",
            "scope": {"domains": ["ai.example.com"], "url_patterns": ["https://ai.example.com/*"]},
            "testing": {"automated_scanning": True},
        }
    )


def _make_handler(requests_seen: list[httpx.Request]):
    def handler(request: httpx.Request) -> httpx.Response:
        requests_seen.append(request)
        url = str(request.url)
        if url == "https://ai.example.com/":
            return httpx.Response(
                200, headers={"content-type": "text/html", "set-cookie": "sid=abc123"}, text=_HTML
            )
        if url == "https://ai.example.com/about":
            return httpx.Response(200, headers={"content-type": "text/html"}, text=_ABOUT_HTML)
        if url == "https://ai.example.com/app.js":
            return httpx.Response(200, headers={"content-type": "application/javascript"}, text=_JS)
        return httpx.Response(404)

    return handler


def _run_discovery(max_pages: int = 5):
    requests_seen: list[httpx.Request] = []
    transport = httpx.MockTransport(_make_handler(requests_seen))
    result = asyncio.run(
        discover_target("https://ai.example.com/", _policy(), max_pages=max_pages, transport=transport)
    )
    return result, requests_seen


def test_discovery_only_ever_sends_get_requests() -> None:
    _, requests_seen = _run_discovery()
    assert len(requests_seen) > 0
    assert all(request.method == "GET" for request in requests_seen)
    assert all(request.content == b"" for request in requests_seen)


def test_discovery_never_fetches_out_of_scope_urls() -> None:
    result, requests_seen = _run_discovery()
    fetched_hosts = {str(request.url) for request in requests_seen}
    assert not any("evil.example.net" in url for url in fetched_hosts)
    assert "https://evil.example.net/out-of-scope" in result.skipped_out_of_scope


def test_discovery_fingerprints_pages_and_follows_same_origin_links() -> None:
    result, _ = _run_discovery()
    fetched = set(result.fetched_urls)
    assert "https://ai.example.com/" in fetched
    assert "https://ai.example.com/about" in fetched
    endpoints = [item for item in result.items if item.asset_type == "endpoint" and item.source_type == "live"]
    locations = {item.location for item in endpoints}
    assert "https://ai.example.com/" in locations
    assert "https://ai.example.com/about" in locations


def test_discovery_extracts_form_and_auth_hints() -> None:
    result, _ = _run_discovery()
    auth_hints = {item.metadata.get("hint") for item in result.items if item.asset_type == "auth"}
    assert "set-cookie" in auth_hints
    assert "password_form" in auth_hints
    form_items = [item for item in result.items if item.metadata.get("method") == "FORM"]
    assert any(item.location == "https://ai.example.com/login" for item in form_items)


def test_discovery_extracts_api_and_websocket_candidates_from_js() -> None:
    result, _ = _run_discovery()
    api_items = [item for item in result.items if item.metadata.get("source") == "js"]
    assert any(item.location == "/api/chat" for item in api_items)
    ws_items = [item for item in result.items if item.asset_type == "websocket"]
    assert any(item.location == "wss://ai.example.com/ws/stream" for item in ws_items)


def test_discovery_flags_exposed_source_map_as_a_secret_signal() -> None:
    result, _ = _run_discovery()
    secret_items = [item for item in result.items if item.asset_type == "secret"]
    assert any(item.metadata.get("secret_type") == "exposed_source_map" for item in secret_items)


def test_discovery_flags_ai_hints_from_page_text() -> None:
    result, _ = _run_discovery()
    llm_items = [item for item in result.items if item.asset_type == "llm"]
    assert llm_items
    assert "chat" in llm_items[0].metadata["hints"]


def test_discovery_respects_max_pages_budget() -> None:
    result, requests_seen = _run_discovery(max_pages=1)
    # only the base page (plus its script, which isn't counted against the
    # page budget) should be fetched -- /about must not be reached
    assert "https://ai.example.com/about" not in result.fetched_urls


def test_discovery_to_dict_is_json_serializable() -> None:
    import json

    result, _ = _run_discovery()
    payload = result.to_dict()
    json.dumps(payload)
    assert payload["base_url"] == "https://ai.example.com/"
    assert payload["attack_surface"]["total"] == len(result.items)
