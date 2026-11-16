import shlex

from integrations.artex_tool_spec import build_spec


def test_art_ex_custom_tool_uses_scoped_bridge_with_shell_quoted_paths(tmp_path):
    repo = tmp_path / "repo path"
    scope = tmp_path / "scope policy.yaml"
    python = tmp_path / "venv path" / "python"
    config = tmp_path / "config target.yaml"
    spec = build_spec(repo, scope, python, config, "llm")
    command = spec["exec"]["command"]
    assert spec["agents"] == ["worker"]
    assert spec["kind"] == "command"
    assert spec["schema"]["required"] == ["url"]
    assert shlex.quote(str(repo)) in command
    assert shlex.quote(str(scope)) in command
    assert shlex.quote(str(python)) in command
    assert shlex.quote(str(config)) in command
    assert "--profile llm" in command
    assert "{url}" in command
    assert "mktemp -d" in command
