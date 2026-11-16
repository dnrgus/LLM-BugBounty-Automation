import json
import subprocess

from integrations.artex_bridge import _artex_assets, run
from cli import main


def test_bridge_marks_only_confirmed_as_graph_findings(tmp_path, monkeypatch):
    output = tmp_path / "scan"
    output.mkdir()
    (output / "summary.json").write_text(json.dumps({
        "target": "http://127.0.0.1:3000", "run_id": "run-1",
        "findings": [
            {"id": "a", "title": "Verified", "status": "confirmed", "path": "high/a"},
            {"id": "b", "title": "Tool alert", "status": "candidate", "path": "needs_review/b"},
            {"id": "c", "title": "Flaky", "status": "unstable", "path": "medium/c"},
        ],
    }), encoding="utf-8")
    (output / "high/a").mkdir(parents=True)
    (output / "high/a/evidence.json").write_text(json.dumps({"response": "observed proof"}), encoding="utf-8")

    def fake_run(command, **kwargs):
        assert command[2:4] == ["scan", "http://127.0.0.1:3000"]
        return subprocess.CompletedProcess(command, 0, json.dumps({
            "mode": "live", "results": {"results_dir": str(output)},
            "discovery": {"attack_surface": {"items": [{"id": "endpoint-1"}]}},
            "pack_selection": [{"pack_id": "web_scan", "selected": True, "reason": "selected"}],
            "pack_runs": [{"pack_id": "web_scan", "tool_id": "nuclei",
                           "status": "skipped_tool_not_installed", "detail": "not installed",
                           "summary": {"raw": "do not publish"}}],
        }), "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = run("http://127.0.0.1:3000", None, output, "quick", 10)
    assert result["ok"] is True
    assert result["assets"] == [{"id": "endpoint-1"}]
    assert result["pack_executions"][0]["status"] == "skipped_tool_not_installed"
    assert "summary" not in result["pack_executions"][0]
    assert [item["graph_kind"] for item in result["findings"]] == ["finding", "candidate", "candidate"]
    assert len(result["findings"][0]["evidence"]["sha256"]) == 64


def test_confirmed_without_evidence_is_only_candidate(tmp_path, monkeypatch):
    output = tmp_path / "scan"
    output.mkdir()
    (output / "summary.json").write_text(json.dumps({
        "target": "http://127.0.0.1:3000", "findings": [
            {"id": "a", "title": "No proof", "status": "confirmed", "path": "high/a"},
        ],
    }), encoding="utf-8")
    monkeypatch.setattr(subprocess, "run", lambda command, **kwargs: subprocess.CompletedProcess(
        command, 0, json.dumps({"mode": "live", "results": {"results_dir": str(output)}}), ""))
    result = run("http://127.0.0.1:3000", None, output, "quick", 10)
    assert result["findings"][0]["graph_kind"] == "candidate"


def test_bridge_does_not_publish_stale_summary_after_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 2, "", "scope denied"))
    result = run("https://example.com", None, tmp_path, "quick", 10)
    assert result["ok"] is False
    assert result["error"] == "scan_failed"
    assert "findings" not in result


def test_bridge_passes_target_adapter_to_real_testcase_packs(tmp_path, monkeypatch):
    config = tmp_path / "target.yaml"
    config.write_text("adapter: custom_http\n", encoding="utf-8")

    def fake_run(command, **kwargs):
        assert command[-4:] == ["--pack-target", "openai", "--pack-target-config", str(config)]
        return subprocess.CompletedProcess(command, 2, "", "invalid test config")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert run("http://127.0.0.1:3000", None, tmp_path, "llm", 10, config)["error"] == "scan_failed"


def test_bridge_timeout_invalid_json_and_empty_result(tmp_path, monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 1)

    monkeypatch.setattr(subprocess, "run", timeout)
    assert run("http://127.0.0.1:3000", None, tmp_path, "quick", 1)["error"] == "scan_timeout"
    monkeypatch.setattr(subprocess, "run", lambda command, **kwargs: subprocess.CompletedProcess(
        command, 0, "not-json", ""))
    assert run("http://127.0.0.1:3000", None, tmp_path, "quick", 1)["error"] == "invalid_scan_output"

    (tmp_path / "summary.json").write_text(json.dumps({
        "target": "http://127.0.0.1:3000", "findings": [],
    }), encoding="utf-8")
    monkeypatch.setattr(subprocess, "run", lambda command, **kwargs: subprocess.CompletedProcess(
        command, 0, json.dumps({"mode": "live", "results": {"results_dir": str(tmp_path)}}), ""))
    result = run("http://127.0.0.1:3000", None, tmp_path, "quick", 1)
    assert result["ok"] is True
    assert result["findings"] == []
    assert result["artex_assets"] == []


def test_scan_rejects_starting_url_outside_explicit_scope(tmp_path, capsys):
    scope = tmp_path / "scope.yaml"
    scope.write_text("scope:\n  domains: [allowed.example]\ntesting:\n  automated_scanning: true\n", encoding="utf-8")
    rc = main(["scan", "https://outside.example/", "--scope", str(scope), "--output", str(tmp_path / "out")])
    assert rc == 3
    assert "outside allowed scope" in json.loads(capsys.readouterr().err)["detail"]
    assert not (tmp_path / "out").exists()


def test_artex_assets_excludes_unobserved_js_paths_and_unknown_methods():
    items = [
        {"asset_type": "endpoint", "location": "https://example.test/api",
         "metadata": {"method": "GET"}},
        {"asset_type": "endpoint", "location": "https://example.test/api",
         "metadata": {"method": "GET"}},
        {"asset_type": "endpoint", "location": "/api/admin",
         "metadata": {"method": "UNKNOWN"}},
    ]
    assert _artex_assets(items) == [{"type": "endpoint", "url": "https://example.test/api", "method": "GET"}]
