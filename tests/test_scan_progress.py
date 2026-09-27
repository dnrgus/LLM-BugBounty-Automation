"""WP-09: the live pipeline emits [n/6] progress lines on stderr only when
asked, so tests and other callers stay quiet by default."""

import asyncio

import httpx
import pytest

from core.orchestrator import run_live_scan_pipeline
from core.profile import load_profile
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore


def _policy() -> PolicyEngine:
    return PolicyEngine.from_yaml("config/scope.example.yaml")


def _handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, headers={"content-type": "text/html"}, text="<html>ok</html>")


def _run(progress: bool, tmp_path) -> None:
    store = SQLiteStore(tmp_path / "p.sqlite")
    profile = load_profile("quick", "config/pipeline.yaml")
    asyncio.run(
        run_live_scan_pipeline(
            _policy(), [], store, profile, "https://ai.example.com/api/",
            progress=progress, transport=httpx.MockTransport(_handler),
        )
    )


def test_progress_lines_emitted_when_enabled(tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
    _run(True, tmp_path)
    err = capsys.readouterr().err
    assert "[1/6] Discovering endpoints..." in err
    assert "[6/6] Writing reports..." not in err  # no output_dir -> no write step
    assert "[4/6] Running scanners..." in err


def test_no_progress_lines_by_default(tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
    _run(False, tmp_path)
    err = capsys.readouterr().err
    assert "[1/6]" not in err
