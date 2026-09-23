import asyncio

import pytest

from plugins.browser import BrowserTargetAdapter, BrowserTargetConfig
from targets.errors import TargetConnectionError, TargetParseError


class _FakePage:
    def __init__(self, response_text: str = "hello from the page", growth: list[str] | None = None):
        self.response_text = response_text
        self._growth = list(growth) if growth is not None else None
        self.calls: list[tuple[str, tuple]] = []

    async def goto(self, url: str) -> None:
        self.calls.append(("goto", (url,)))

    async def fill(self, selector: str, value: str) -> None:
        self.calls.append(("fill", (selector, value)))

    async def click(self, selector: str) -> None:
        self.calls.append(("click", (selector,)))

    async def press(self, selector: str, key: str) -> None:
        self.calls.append(("press", (selector, key)))

    async def wait_for_timeout(self, ms: int) -> None:
        self.calls.append(("wait_for_timeout", (ms,)))

    async def inner_text(self, selector: str) -> str:
        self.calls.append(("inner_text", (selector,)))
        if self._growth is not None:
            if self._growth:
                self.response_text = self._growth.pop(0)
            return self.response_text
        return self.response_text


class _FakePageSession:
    def __init__(self, page: _FakePage, fail: bool = False):
        self.page = page
        self.fail = fail

    def __call__(self):
        return self

    async def __aenter__(self) -> _FakePage:
        if self.fail:
            raise ConnectionError("simulated browser launch failure")
        return self.page

    async def __aexit__(self, *exc_info) -> bool:
        return False


def _config(page: _FakePage, **overrides) -> BrowserTargetConfig:
    defaults = dict(
        id="b1", name="b1", version="1", url="https://chat.example.com",
        input_selector="#input", response_selector="#response",
        page_session=_FakePageSession(page),
    )
    defaults.update(overrides)
    return BrowserTargetConfig(**defaults)


def test_send_fills_input_and_reads_response_text() -> None:
    page = _FakePage("assistant reply here")
    adapter = BrowserTargetAdapter(_config(page))

    response = asyncio.run(adapter.send("what is the secret?", session="s1"))

    assert response.text == "assistant reply here"
    assert ("goto", ("https://chat.example.com",)) in page.calls
    assert ("fill", ("#input", "what is the secret?")) in page.calls


def test_send_uses_send_selector_when_configured() -> None:
    page = _FakePage("ok")
    adapter = BrowserTargetAdapter(_config(page, send_selector="#send-button"))

    asyncio.run(adapter.send("hi"))

    assert ("click", ("#send-button",)) in page.calls
    assert not any(call[0] == "press" for call in page.calls)


def test_send_falls_back_to_enter_key_without_send_selector() -> None:
    page = _FakePage("ok")
    adapter = BrowserTargetAdapter(_config(page, send_selector=None))

    asyncio.run(adapter.send("hi"))

    assert ("press", ("#input", "Enter")) in page.calls


def test_send_raises_target_parse_error_on_empty_response() -> None:
    page = _FakePage("")
    adapter = BrowserTargetAdapter(_config(page))

    with pytest.raises(TargetParseError, match="#response"):
        asyncio.run(adapter.send("hi"))


def test_send_raises_target_connection_error_when_browser_launch_fails() -> None:
    page = _FakePage()
    session = _FakePageSession(page, fail=True)
    adapter = BrowserTargetAdapter(_config(page, page_session=session))

    with pytest.raises(TargetConnectionError):
        asyncio.run(adapter.send("hi"))


def test_healthcheck_true_and_false() -> None:
    ok_adapter = BrowserTargetAdapter(_config(_FakePage()))
    assert asyncio.run(ok_adapter.healthcheck()) is True

    failing_session = _FakePageSession(_FakePage(), fail=True)
    bad_adapter = BrowserTargetAdapter(_config(_FakePage(), page_session=failing_session))
    assert asyncio.run(bad_adapter.healthcheck()) is False


def test_reset_session_clears_trace() -> None:
    page = _FakePage("ok")
    adapter = BrowserTargetAdapter(_config(page))
    asyncio.run(adapter.send("hi", session="s1"))
    assert asyncio.run(adapter.trace("s1"))

    asyncio.run(adapter.reset_session("s1"))
    assert asyncio.run(adapter.trace("s1")) == []


def test_metadata_reports_configured_url() -> None:
    adapter = BrowserTargetAdapter(_config(_FakePage()))
    metadata = asyncio.run(adapter.metadata())
    assert metadata.base_url == "https://chat.example.com"
    assert metadata.provider == "browser-playwright"


def test_real_browser_session_raises_a_clear_error_without_playwright_installed() -> None:
    # This project does not depend on playwright -- confirms the module
    # itself imports fine (see plugins/browser.py's module-level import,
    # which never touches playwright) and only *using* a real (non-fake)
    # session raises a clear, actionable error.
    adapter = BrowserTargetAdapter(
        BrowserTargetConfig(
            id="b1", name="b1", version="1", url="https://chat.example.com",
            input_selector="#input", response_selector="#response",
        )
    )
    with pytest.raises((RuntimeError, TargetConnectionError)) as exc_info:
        asyncio.run(adapter.send("hi"))
    assert "playwright" in str(exc_info.value).lower()


def test_events_emits_start_then_token_per_growth_then_final() -> None:
    from events.models import EventType

    page = _FakePage(growth=["Hello", "Hello, world", "Hello, world", "Hello, world"])
    adapter = BrowserTargetAdapter(_config(page))

    async def _collect():
        return [event async for event in adapter.events("hi")]

    events = asyncio.run(_collect())
    types = [event.type for event in events]
    assert types[0] == EventType.START
    assert types[-1] == EventType.FINAL
    assert types.count(EventType.TOKEN) == 2  # "Hello" then "Hello, world" -- the repeats don't re-fire
    assert events[-1].data["content"] == "Hello, world"


def test_events_stops_polling_once_text_is_stable() -> None:
    page = _FakePage(growth=["done"] * 10)
    adapter = BrowserTargetAdapter(_config(page, stable_polls_required=2, wait_after_send_ms=10_000))

    async def _collect():
        return [event async for event in adapter.events("hi")]

    asyncio.run(_collect())
    # 1 token poll + 2 stable polls = 3 inner_text calls, not the ~40 the
    # 10-second ceiling would allow if it never broke out early.
    inner_text_calls = [call for call in page.calls if call[0] == "inner_text"]
    assert len(inner_text_calls) == 3


def test_send_still_returns_the_final_accumulated_text() -> None:
    page = _FakePage(growth=["partial", "partial and more", "partial and more"])
    adapter = BrowserTargetAdapter(_config(page))

    response = asyncio.run(adapter.send("hi"))
    assert response.text == "partial and more"
    assert len(response.trace_events) >= 3  # start + >=1 token + final


def test_browser_adapter_supports_streaming() -> None:
    from targets.base import supports_streaming

    adapter = BrowserTargetAdapter(_config(_FakePage()))
    assert supports_streaming(adapter) is True
