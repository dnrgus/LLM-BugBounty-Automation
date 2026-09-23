from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable

from core.models import CapabilityProfile, TraceEvent
from events.models import Event, EventType
from plugins.registry import register_plugin
from targets.base import TargetMetadata, TargetResponse
from targets.errors import TargetConnectionError, TargetParseError


@dataclass(frozen=True)
class BrowserTargetConfig:
    """Drives an actual web chat UI via Playwright, for a target that
    exposes no clean API at all -- the last-resort adapter kind. All
    selectors are configurable since every chat UI's DOM differs; there
    is no universal "the chat box" selector.
    """

    id: str
    name: str
    version: str
    url: str
    input_selector: str
    response_selector: str
    send_selector: str | None = None
    browser_type: str = "chromium"
    headless: bool = True
    # P4.3-D (roadmap v4.3.0 Runtime Coverage Expansion): wait_after_send_ms
    # is now a *ceiling*, not a single fixed sleep -- the page is polled
    # every poll_interval_ms and a TOKEN event is emitted each time the
    # response element's text grows, stopping early once it's stayed the
    # same for stable_polls_required consecutive polls (or the ceiling is
    # reached). A YAML config that only sets wait_after_send_ms keeps
    # working exactly as before, just with real intermediate events now.
    wait_after_send_ms: int = 2000
    poll_interval_ms: int = 250
    stable_polls_required: int = 2
    capabilities: dict[str, bool] = field(default_factory=lambda: {"chat": True})
    page_session: Callable[[], Any] | None = None  # injectable async context manager factory, for tests


class BrowserTargetAdapter:
    """U12 Browser Plugin SDK (design doc section 14, "Playwright
    optional"): a TargetAdapter for a web chat UI that has no API at
    all. Playwright is imported lazily, inside _RealBrowserSession, so
    this module -- and the "browser" plugin it registers -- loads and is
    listed in registered_plugin_names() fine even when Playwright isn't
    installed; only actually calling send()/healthcheck() requires it,
    with a clear error if it's missing.

    P4.3-D (roadmap v4.3.0 Runtime Coverage Expansion): implements the
    StreamingTargetAdapter protocol's events() too, honestly scoped to
    what DOM polling can actually observe -- there is no real push-based
    stream here the way WebSocket/SSE have one, so a TOKEN event is
    emitted whenever the response element's text is observed to have
    grown between polls, not as each token is truly generated. send()
    is built on top of events(), the same shared-source-of-truth shape
    events/sse_target.py and events/websocket_target.py already use.
    """

    def __init__(self, config: BrowserTargetConfig):
        self.config = config
        self._trace: dict[str, list[TraceEvent]] = {}

    async def healthcheck(self) -> bool:
        try:
            async with self._page_session() as page:
                await page.goto(self.config.url)
            return True
        except Exception:
            return False

    async def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            id=self.config.id,
            kind="llm",
            provider="browser-playwright",
            name=self.config.name,
            version=self.config.version,
            base_url=self.config.url,
        )

    async def capabilities(self) -> CapabilityProfile:
        return CapabilityProfile(**self.config.capabilities)

    async def events(self, prompt: str, session: str | None = None) -> AsyncIterator[Event]:
        sequence = 0

        try:
            async with self._page_session() as page:
                await page.goto(self.config.url)
                sequence += 1
                yield Event(type=EventType.START, sequence=sequence, data={"url": self.config.url})

                await page.fill(self.config.input_selector, prompt)
                if self.config.send_selector:
                    await page.click(self.config.send_selector)
                else:
                    await page.press(self.config.input_selector, "Enter")

                previous_text = ""
                stable_polls = 0
                elapsed_ms = 0
                while elapsed_ms < self.config.wait_after_send_ms:
                    await page.wait_for_timeout(self.config.poll_interval_ms)
                    elapsed_ms += self.config.poll_interval_ms
                    current_text = await page.inner_text(self.config.response_selector)
                    if current_text and current_text != previous_text:
                        sequence += 1
                        yield Event(
                            type=EventType.TOKEN, sequence=sequence,
                            data={"content": current_text, "response_selector": self.config.response_selector},
                        )
                        previous_text = current_text
                        stable_polls = 0
                    elif previous_text:
                        stable_polls += 1
                        if stable_polls >= self.config.stable_polls_required:
                            break

                if not previous_text:
                    previous_text = await page.inner_text(self.config.response_selector)
        except (TargetConnectionError, TargetParseError):
            raise
        except Exception as exc:
            raise TargetConnectionError(f"browser automation against {self.config.url} failed: {exc}") from exc

        if not previous_text:
            raise TargetParseError(f"no text found at selector '{self.config.response_selector}'")

        sequence += 1
        yield Event(type=EventType.FINAL, sequence=sequence, data={"content": previous_text})

    async def send(self, prompt: str, session: str | None = None) -> TargetResponse:
        session_id = session or "default"
        session_events = self._trace.setdefault(session_id, [])
        call_trace_events: list[TraceEvent] = []
        text = ""

        async for event in self.events(prompt, session_id):
            trace_event = _to_trace_event(session_id, event)
            session_events.append(trace_event)
            call_trace_events.append(trace_event)
            if event.type == EventType.FINAL:
                text = str(event.data.get("content", ""))

        return TargetResponse(prompt=prompt, text=text, metadata={"session": session_id}, trace_events=call_trace_events)

    async def reset_session(self, session: str | None = None) -> None:
        self._trace.pop(session or "default", None)

    async def trace(self, session: str | None = None) -> list[TraceEvent]:
        if session is None:
            return [event for events in self._trace.values() for event in events]
        return list(self._trace.get(session, []))

    def _page_session(self) -> Any:
        if self.config.page_session is not None:
            return self.config.page_session()
        return _RealBrowserSession(self.config.browser_type, self.config.headless)


class _RealBrowserSession:
    """Lazily imports and drives the real Playwright async API. Only
    reached when no fake page_session was injected -- i.e. never during
    this project's own tests, only for a real browser target."""

    def __init__(self, browser_type: str, headless: bool):
        self._browser_type = browser_type
        self._headless = headless
        self._playwright: Any = None
        self._browser: Any = None

    async def __aenter__(self) -> Any:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError(
                "Browser automation requires the optional 'playwright' package: "
                f"pip install playwright && playwright install {self._browser_type}"
            ) from exc
        self._playwright = await async_playwright().start()
        launcher = getattr(self._playwright, self._browser_type)
        self._browser = await launcher.launch(headless=self._headless)
        return await self._browser.new_page()

    async def __aexit__(self, *exc_info: object) -> bool:
        if self._browser is not None:
            await self._browser.close()
        if self._playwright is not None:
            await self._playwright.stop()
        return False


def _build_browser_target(target: dict[str, Any]) -> BrowserTargetAdapter:
    if "base_url" not in target:
        raise ValueError("browser target manifest is missing required field 'base_url'")
    selectors = target.get("selectors") or {}
    if "input" not in selectors or "response" not in selectors:
        raise ValueError("browser target manifest requires selectors.input and selectors.response")

    return BrowserTargetAdapter(
        BrowserTargetConfig(
            id=str(target.get("id", "browser")),
            name=str(target.get("name", target.get("id", "browser"))),
            version=str(target.get("version", "unknown")),
            url=str(target["base_url"]),
            input_selector=str(selectors["input"]),
            response_selector=str(selectors["response"]),
            send_selector=selectors.get("send"),
            browser_type=str(target.get("browser_type", "chromium")),
            headless=bool(target.get("headless", True)),
            wait_after_send_ms=int(target.get("wait_after_send_ms", 2000)),
            poll_interval_ms=int(target.get("poll_interval_ms", 250)),
            stable_polls_required=int(target.get("stable_polls_required", 2)),
            capabilities=dict(target.get("capabilities") or {"chat": True}),
        )
    )


def _to_trace_event(session_id: str, event: Event) -> TraceEvent:
    return TraceEvent(trace_id=session_id, sequence=event.sequence, event_type=event.type.value, metadata=event.data)


register_plugin("browser", _build_browser_target)
