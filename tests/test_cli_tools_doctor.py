"""WP-02: `bugbounty tools` command and the `doctor` core/optional summary.

Both reuse core.tool_doctor.check_tools; a temp tools.yaml keeps the tests
independent of whatever is actually installed on the machine.
"""

import json
from pathlib import Path

import pytest

from cli import main


def _write_tools(tmp_path: Path) -> Path:
    cfg = tmp_path / "tools.yaml"
    cfg.write_text(
        "tools:\n"
        "  nuclei:\n    enabled: true\n    category: web_scanner\n"
        "  definitely_not_a_real_tool_xyz:\n    enabled: true\n    category: static_analysis\n",
        encoding="utf-8",
    )
    return cfg


def test_tools_command_lists_status_and_purpose(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = _write_tools(tmp_path)
    rc = main(["tools", "--tools", str(cfg)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Tool" in out and "Status" in out and "Purpose" in out
    # The bogus tool is never installed, so it must render as Missing.
    assert "definitely_not_a_real_tool_xyz" in out
    assert "Missing" in out
    assert "Dynamic / DAST" in out  # nuclei's purpose label


def test_tools_command_json_is_machine_readable(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = _write_tools(tmp_path)
    rc = main(["tools", "--tools", str(cfg), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    names = {t["name"] for t in payload["tools"]}
    assert names == {"nuclei", "definitely_not_a_real_tool_xyz"}
    bogus = next(t for t in payload["tools"] if t["name"] == "definitely_not_a_real_tool_xyz")
    assert bogus["available"] is False


def test_doctor_reports_core_ready_and_missing_optionals(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = _write_tools(tmp_path)
    rc = main(["doctor", "--tools", str(cfg)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Core pipeline ready." in out
    # The bogus tool is missing, so it must be surfaced as a degraded optional.
    assert "definitely_not_a_real_tool_xyz" in out
