"""WP-03: ScanContext -- the single object a `bugbounty scan` run threads
through discovery, scanners, verification and reporting.

It is a thin aggregation of things the CLI already passes around as loose
arguments (target, source, scope, output location) plus two additions the
later work packages need in one shared place: authentication (WP-05, so a
token is entered once and reused by every scanner adapter) and a discovered
endpoint registry (WP-06/08, so scanners don't each re-crawl). Nothing here
runs a scan; it only carries state, so it can be constructed and asserted on
in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DEFAULT_RESULTS_DIRNAME = "BugBounty-Results"


@dataclass
class AuthContext:
    """Credentials entered once and reused by every scanner adapter (§19).

    Never stringify this into a report or log directly -- use
    as_request_headers() at the point of use and rely on
    reporting.sanitizer for anything persisted. __repr__ is masked so an
    accidental f-string or traceback can't leak the token.
    """

    token: str | None = None
    headers: dict[str, str] = field(default_factory=dict)

    def as_request_headers(self) -> dict[str, str]:
        """Merge the bearer token and any explicit headers into the header
        dict a scanner should send. Explicit headers win over the derived
        Authorization header so a caller can override it deliberately.
        """
        merged: dict[str, str] = {}
        if self.token:
            merged["Authorization"] = f"Bearer {self.token}"
        merged.update(self.headers)
        return merged

    @property
    def is_present(self) -> bool:
        return bool(self.token) or bool(self.headers)

    def __repr__(self) -> str:  # pragma: no cover - trivial masking
        token = "***" if self.token else None
        keys = sorted(self.headers)
        return f"AuthContext(token={token!r}, header_keys={keys!r})"


def target_slug(target: str | None, source_path: Path | str | None) -> str:
    """A filesystem-safe label for the run's output directory.

    URL -> host_port (e.g. http://127.0.0.1:3000 -> 127.0.0.1_3000);
    source-only -> the source directory name; nothing -> "scan".
    """
    if target:
        parsed = urlparse(target if "://" in target else f"//{target}")
        host = parsed.hostname or target
        label = host if parsed.port is None else f"{host}_{parsed.port}"
    elif source_path is not None:
        label = Path(source_path).resolve().name or "source"
    else:
        label = "scan"
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in label)
    return safe.strip("_") or "scan"


@dataclass
class ScanContext:
    target: str | None = None
    source_path: Path | None = None
    scope_path: Path | None = None
    profile: str = "quick"
    max_pages: int = 5
    verbose: bool = False
    auth: AuthContext = field(default_factory=AuthContext)
    output_dir: Path = field(default_factory=lambda: Path(DEFAULT_RESULTS_DIRNAME))
    # Populated during the scan; a shared endpoint registry (WP-06/08) so
    # scanners reuse discovery instead of each re-crawling.
    endpoints: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        target: str | None = None,
        source_path: Path | None = None,
        *,
        scope_path: Path | None = None,
        profile: str = "quick",
        max_pages: int = 5,
        verbose: bool = False,
        auth: AuthContext | None = None,
        results_base: Path | str = DEFAULT_RESULTS_DIRNAME,
        now: datetime | None = None,
    ) -> "ScanContext":
        stamp = (now or datetime.now()).strftime("%Y-%m-%d_%H%M%S")
        output_dir = Path(results_base) / f"{target_slug(target, source_path)}_{stamp}"
        return cls(
            target=target,
            source_path=Path(source_path) if source_path is not None else None,
            scope_path=Path(scope_path) if scope_path is not None else None,
            profile=profile,
            max_pages=max_pages,
            verbose=verbose,
            auth=auth or AuthContext(),
            output_dir=output_dir,
        )

    @property
    def mode(self) -> str:
        if self.target and self.source_path:
            return "hybrid"
        if self.source_path:
            return "source"
        if self.target:
            return "live"
        return "fixture"
