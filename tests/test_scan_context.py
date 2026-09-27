"""WP-03: ScanContext aggregation, output-dir slug, and auth redaction."""

from datetime import datetime
from pathlib import Path

from core.scan_context import AuthContext, ScanContext, target_slug


def test_target_slug_from_url_uses_host_and_port() -> None:
    assert target_slug("http://127.0.0.1:3000", None) == "127.0.0.1_3000"
    assert target_slug("https://example.com/api/", None) == "example.com"


def test_target_slug_from_source_uses_dir_name() -> None:
    assert target_slug(None, Path("/tmp/juice-shop")) == "juice-shop"


def test_target_slug_falls_back_to_scan() -> None:
    assert target_slug(None, None) == "scan"


def test_mode_detection() -> None:
    assert ScanContext(target="http://x").mode == "live"
    assert ScanContext(source_path=Path("./p")).mode == "source"
    assert ScanContext(target="http://x", source_path=Path("./p")).mode == "hybrid"
    assert ScanContext().mode == "fixture"


def test_create_builds_timestamped_output_dir_under_base(tmp_path: Path) -> None:
    ctx = ScanContext.create(
        target="http://127.0.0.1:3000",
        results_base=tmp_path,
        now=datetime(2026, 9, 26, 10, 30, 0),
    )
    assert ctx.output_dir == tmp_path / "127.0.0.1_3000_2026-09-26_103000"
    assert ctx.mode == "live"


def test_auth_context_builds_bearer_header_and_merges_explicit() -> None:
    auth = AuthContext(token="abc123", headers={"X-Api-Key": "k"})
    headers = auth.as_request_headers()
    assert headers["Authorization"] == "Bearer abc123"
    assert headers["X-Api-Key"] == "k"
    assert auth.is_present is True


def test_auth_context_explicit_authorization_overrides_token() -> None:
    auth = AuthContext(token="abc123", headers={"Authorization": "Bearer override"})
    assert auth.as_request_headers()["Authorization"] == "Bearer override"


def test_auth_context_repr_masks_token() -> None:
    auth = AuthContext(token="super-secret-token", headers={"X-Api-Key": "k"})
    rendered = repr(auth)
    assert "super-secret-token" not in rendered
    assert "***" in rendered


def test_empty_auth_is_not_present() -> None:
    assert AuthContext().is_present is False
    assert AuthContext().as_request_headers() == {}
