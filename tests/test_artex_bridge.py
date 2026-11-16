import json
import subprocess

from integrations.artex_bridge import run


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

    def fake_run(command, **kwargs):
        assert command[2:4] == ["scan", "http://127.0.0.1:3000"]
        return subprocess.CompletedProcess(command, 0, json.dumps({
            "mode": "live", "results": {"results_dir": str(output)},
            "discovery": {"attack_surface": {"items": [{"id": "endpoint-1"}]}},
        }), "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = run("http://127.0.0.1:3000", None, output, "quick", 10)
    assert result["ok"] is True
    assert result["assets"] == [{"id": "endpoint-1"}]
    assert [item["graph_kind"] for item in result["findings"]] == ["finding", "candidate", "candidate"]


def test_bridge_does_not_publish_stale_summary_after_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 2, "", "scope denied"))
    result = run("https://example.com", None, tmp_path, "quick", 10)
    assert result["ok"] is False
    assert result["error"] == "scan_failed"
    assert "findings" not in result
