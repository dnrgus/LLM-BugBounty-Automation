"""P5.0 WP-10 (v5.0 plan 8.3): the release gate checklist."""

import json

import pytest

import core.release_check as release_check
from cli import main


def test_all_release_gates_pass(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["release-check"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert [gate["id"] for gate in result["gates"]] == [f"G{i}" for i in range(1, 11)]
    assert all(gate["passed"] for gate in result["gates"])


def test_failing_gate_is_reported_and_exits_1(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    def broken() -> str:
        raise AssertionError("simulated scope bypass")

    gates = tuple((gid, title, broken if gid == "G2" else fn) for gid, title, fn in release_check.GATES)
    monkeypatch.setattr(release_check, "GATES", gates)
    assert main(["release-check", "--gate", "G2", "--gate", "G3"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert [(g["id"], g["passed"]) for g in result["gates"]] == [("G2", False), ("G3", True)]
    assert result["gates"][0]["detail"] == "simulated scope bypass"
