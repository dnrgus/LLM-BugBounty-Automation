from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from core.models import CapabilityProfile, TraceEvent
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
    wait_after_send_ms: int = 2000
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

    async def send(self, prompt: str, session: str | None = None) -> TargetResponse:
        session_id = session or "default"
        events = self._trace.setdefault(session_id, [])

        try:
            async with self._page_session() as page:
                await page.goto(self.config.url)
                await page.fill(self.config.input_selector, prompt)
                if self.config.send_selector:
                    await page.click(self.config.send_selector)
                else:
                    await page.press(self.config.input_selector, "Enter")
                await page.wait_for_timeout(self.config.wait_after_send_ms)
                text = await page.inner_text(self.config.response_selector)
        except (TargetConnectionError, TargetParseError):
            raise
        except Exception as exc:
            raise TargetConnectionError(f"browser automation against {self.config.url} failed: {exc}") from exc

        if not text:
            raise TargetParseError(f"no text found at selector '{self.config.response_selector}'")

        event = TraceEvent(
            trace_id=session_id,
            sequence=len(events) + 1,
            event_type="browser_interaction",
            metadata={"url": self.config.url, "response_selector": self.config.response_selector},
        )
        events.append(event)
        return TargetResponse(prompt=prompt, text=text, metadata={"session": session_id}, trace_events=[event])

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
            capabilities=dict(target.get("capabilities") or {"chat": True}),
        )
    )


register_plugin("browser", _build_browser_target)
