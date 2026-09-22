from __future__ import annotations

import asyncio


class OperationCancelled(Exception):
    """Raised by CancellationToken.raise_if_cancelled(). Deliberately its
    own type, not asyncio.CancelledError -- that one is reserved for
    asyncio's own task-cancellation machinery (raising it from arbitrary
    application code can confuse task/future cancellation elsewhere)."""


class CancellationToken:
    """P3.4-2 (roadmap v3.4.0 Production Hardening): a cooperative
    cancellation signal threaded through a run. Checked at safe points
    (before starting a new testcase, before spawning an external tool
    subprocess) rather than forcibly interrupting work mid-flight, so an
    in-flight request or subprocess is always given the chance to record
    its own outcome (this project's evidence/checkpoint writes) before
    the caller acts on the cancellation.
    """

    def __init__(self) -> None:
        self._event = asyncio.Event()
        self.reason: str | None = None

    def cancel(self, reason: str = "cancelled by caller") -> None:
        self.reason = reason
        self._event.set()

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self.is_cancelled:
            raise OperationCancelled(self.reason or "cancelled")

    async def wait(self) -> None:
        await self._event.wait()


class BoundedConcurrency:
    """P3.4-2's "bounded queue/concurrency" primitive -- a named
    asyncio.Semaphore wrapper. `limit=None` (or 0) means unbounded: a
    no-op async context manager, so wrapping existing sequential code in
    it is always behavior-preserving when no limit is configured
    (matching scope config's own optional `limits.concurrency`).
    """

    def __init__(self, limit: int | None) -> None:
        self.limit = limit
        self._semaphore = asyncio.Semaphore(limit) if limit and limit > 0 else None
        self.in_flight = 0
        self.max_in_flight_seen = 0

    async def __aenter__(self) -> "BoundedConcurrency":
        if self._semaphore is not None:
            await self._semaphore.acquire()
        self.in_flight += 1
        self.max_in_flight_seen = max(self.max_in_flight_seen, self.in_flight)
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        self.in_flight -= 1
        if self._semaphore is not None:
            self._semaphore.release()
