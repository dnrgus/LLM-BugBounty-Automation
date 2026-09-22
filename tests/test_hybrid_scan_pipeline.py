"""P3.3-4 Hybrid CLI completion (roadmap v3.3.0 Static -> Dynamic Validation).

End-to-end test of `scan <url> --source <path>`'s internal API
(core.orchestrator.run_hybrid_scan_pipeline), wiring together every
building block from P3.3-1 through P3.3-3.
"""

import asyncio
import json
from pathlib import Path

import httpx

from core.orchestrator import run_hybrid_scan_pipeline
from core.profile import load_profile
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from testcase.loader import load_testcases

_APP_PY = (
    "import openai\n"
    "from flask import Flask, request\n\n"
    "app = Flask(__name__)\n\n"
    "@app.route('/api/chat', methods=['POST'])\n"
    "def chat():\n"
    "    message = request.json.get('message')\n"
    "    return openai.ChatCompletion.create(model='gpt-4', messages=[{'role': 'user', 'content': message}])\n"
)

_LIVE_HTML = '<html><body>This is an AI chat assistant.<form action="/api/chat"></form></body></html>'
_TARGET_URL = "https://ai.example.com/api/chat"


def _policy() -> PolicyEngine:
    return PolicyEngine.from_yaml("config/scope.example.yaml")


def _testcases():
    return load_testcases("testcase/suites/basic.yaml")


def _write_source(tmp_path: Path) -> Path:
    source_root = tmp_path / "src"
    source_root.mkdir()
    (source_root / "app.py").write_text(_APP_PY, encoding="utf-8")
    return source_root


def _transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html"}, text=_LIVE_HTML)

    return httpx.MockTransport(handler)


def _run(source_root: Path, tmp_path: Path, **kwargs):
    store = SQLiteStore(tmp_path / "hybrid.sqlite")
    profile = load_profile("quick", "config/pipeline.yaml")
    return asyncio.run(
        run_hybrid_scan_pipeline(
            _policy(), _testcases(), store, profile, _TARGET_URL,
            source_root, transport=_transport(), **kwargs
        )
    )


def test_hybrid_scan_produces_static_live_and_correlated_sections(tmp_path: Path) -> None:
    source_root = _write_source(tmp_path)
    result = _run(source_root, tmp_path, pack_target="fake-llm")

    assert result["mode"] == "hybrid"
    assert result["static_findings"]["total"] > 0
    assert any(item["asset_type"] == "llm" for item in result["static_findings"]["items"])
    assert result["live_findings"]["discovery"]["attack_surface"]["total"] > 0
    assert result["entity_matches"]
    assert result["validation_plans"]


def test_hybrid_scan_dynamically_validates_the_llm_capability_hint_and_confirms_a_finding(tmp_path: Path) -> None:
    source_root = _write_source(tmp_path)
    result = _run(source_root, tmp_path, pack_target="fake-llm")

    assert len(result["dynamic_validation_runs"]) == 1
    run = result["dynamic_validation_runs"][0]
    assert run["status"] == "ran"
    assert result["correlated_findings"]
    assert any(cf["finding_status"] == "confirmed" for cf in result["correlated_findings"])
    assert all(cf["origin"] == ["static", "dynamic"] for cf in result["correlated_findings"])
    assert result["finding_count"] > 0
    assert result["clusters"]


def test_hybrid_scan_without_a_pack_target_runs_no_dynamic_validation(tmp_path: Path) -> None:
    source_root = _write_source(tmp_path)
    result = _run(source_root, tmp_path)  # no pack_target

    assert result["dynamic_validation_runs"] == []
    assert result["correlated_findings"] == []
    assert result["finding_count"] == 0


def test_hybrid_scan_duplicate_live_matches_still_run_dynamic_validation_only_once(tmp_path: Path) -> None:
    # discover_target's own fingerprinting produces more than one live
    # "endpoint" item for this fixture page (the page fingerprint itself,
    # plus a <form action="/api/chat"> pointing right back at it) --
    # multiple EntityMatches for the same source candidate must not
    # multiply how many times it gets dynamically validated.
    source_root = _write_source(tmp_path)
    result = _run(source_root, tmp_path, pack_target="fake-llm")

    live_endpoints_at_chat = [
        item for item in result["live_findings"]["discovery"]["attack_surface"]["items"]
        if item["asset_type"] == "endpoint" and item["location"].endswith("/api/chat")
    ]
    assert len(live_endpoints_at_chat) >= 2  # the duplicate live signal actually exists in this fixture
    assert len(result["dynamic_validation_runs"]) == 1  # but only validated once


def test_hybrid_scan_result_is_json_serializable(tmp_path: Path) -> None:
    source_root = _write_source(tmp_path)
    result = _run(source_root, tmp_path, pack_target="fake-llm")
    json.dumps(result)
