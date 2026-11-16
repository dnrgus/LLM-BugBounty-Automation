import json
import subprocess
import sys
from pathlib import Path

from integrations.artex_tool_spec import build_spec


def test_artex_custom_tool_uses_scoped_bridge_without_shell(tmp_path):
    repo = tmp_path / "repo path"
    scope = tmp_path / "scope policy.yaml"
    python = tmp_path / "venv path" / "python"
    config = tmp_path / "config target.yaml"
    spec = build_spec(repo, scope, python, config, "llm")
    code = spec["exec"]["code"]
    compile(code, "<artex-custom-tool>", "exec")
    assert spec["agents"] == ["worker"]
    assert spec["kind"] == "script"
    assert spec["schema"]["required"] == ["url"]
    assert str(repo) in code
    assert str(scope) in code
    assert str(python) in code
    assert str(config) in code
    assert "'--profile', 'llm'" in code
    assert "subprocess.run" in code
    assert "tempfile.mkdtemp" in code


def test_generated_script_preserves_scope_rejection():
    repo = Path(__file__).resolve().parents[1]
    spec = build_spec(repo, repo / "config/scope.example.yaml", Path(sys.executable))
    result = subprocess.run(
        [sys.executable, "-c", spec["exec"]["code"]],
        input=json.dumps({"url": "https://example.com"}), capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0
    output = json.loads(result.stdout)
    assert output["ok"] is False
    assert output["error"] == "scan_failed"
