import json
import subprocess
import sys
from pathlib import Path

from adapters.discovery.ffuf import FfufAdapter
from adapters.discovery.katana import KatanaAdapter
from adapters.recon.httpx import HttpxAdapter
from adapters.recon.subfinder import SubfinderAdapter
from recon.pipeline import build_asset_map
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore

FIXTURES = Path("tests/fixtures/tools")


def test_subfinder_adapter_parses_and_dedups_hosts() -> None:
    assets = SubfinderAdapter().parse_file(
        FIXTURES / "subfinder-results.jsonl", run_id="run_1", target_id="target_1"
    )
    assert [asset.domain for asset in assets] == [
        "ai.example.com",
        "admin.ai.example.com",
        "shadow.example.net",
    ]
    assert all(asset.source == "subfinder" for asset in assets)


def test_httpx_adapter_parses_endpoints() -> None:
    endpoints = HttpxAdapter().parse_file(FIXTURES / "httpx-results.jsonl", run_id="run_1", target_id="target_1")
    assert len(endpoints) == 3
    assert endpoints[0].url == "https://ai.example.com/api/chat"
    assert endpoints[0].status_code == 200
    assert endpoints[0].metadata["webserver"] == "nginx"


def test_katana_adapter_parses_endpoints() -> None:
    endpoints = KatanaAdapter().parse_file(FIXTURES / "katana-results.jsonl", run_id="run_1", target_id="target_1")
    assert len(endpoints) == 2
    assert endpoints[0].method == "GET"
    assert endpoints[1].method == "POST"
    assert endpoints[1].status_code == 403


def test_ffuf_adapter_parses_endpoints() -> None:
    endpoints = FfufAdapter().parse_file(FIXTURES / "ffuf-results.json", run_id="run_1", target_id="target_1")
    assert len(endpoints) == 2
    assert endpoints[0].url == "https://ai.example.com/api/tools"
    assert endpoints[0].metadata["words"] == 40


def test_policy_validate_domain_matches_deny_and_allow_lists() -> None:
    engine = PolicyEngine.from_yaml("config/scope.example.yaml")
    assert engine.validate_domain("ai.example.com").allowed
    assert not engine.validate_domain("admin.ai.example.com").allowed
    assert not engine.validate_domain("shadow.example.net").allowed


def test_build_asset_map_revalidates_scope(tmp_path: Path) -> None:
    policy = PolicyEngine.from_yaml("config/scope.example.yaml")
    store = SQLiteStore(tmp_path / "recon.sqlite")
    result = build_asset_map(
        policy,
        store,
        run_id="run_1",
        target_id="target_1",
        subfinder_input=FIXTURES / "subfinder-results.jsonl",
        httpx_input=FIXTURES / "httpx-results.jsonl",
        katana_input=FIXTURES / "katana-results.jsonl",
        ffuf_input=FIXTURES / "ffuf-results.json",
    )
    assert result["assets"]["total"] == 3
    assert result["assets"]["in_scope"] == 1
    assert result["assets"]["out_of_scope"] == 2
    assert result["endpoints"]["total"] == 7
    assert result["endpoints"]["in_scope"] == 3
    assert result["endpoints"]["out_of_scope"] == 4
    assert result["endpoints"]["by_source"] == {"httpx": 3, "katana": 2, "ffuf": 2}

    with store.connect() as conn:
        asset_rows = conn.execute("select domain, in_scope from assets").fetchall()
        endpoint_rows = conn.execute("select url, in_scope from endpoints").fetchall()
    assert len(asset_rows) == 3
    assert len(endpoint_rows) == 7
    assert {row["domain"]: bool(row["in_scope"]) for row in asset_rows}["ai.example.com"] is True
    assert {row["domain"]: bool(row["in_scope"]) for row in asset_rows}["admin.ai.example.com"] is False


def test_recon_cli_outputs_json(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "recon",
            "--subfinder-input",
            str(FIXTURES / "subfinder-results.jsonl"),
            "--httpx-input",
            str(FIXTURES / "httpx-results.jsonl"),
            "--katana-input",
            str(FIXTURES / "katana-results.jsonl"),
            "--ffuf-input",
            str(FIXTURES / "ffuf-results.json"),
            "--db",
            str(tmp_path / "recon_cli.sqlite"),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(result.stdout)
    assert payload["assets"]["total"] == 3
    assert payload["endpoints"]["total"] == 7
