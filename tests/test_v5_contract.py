"""P5.0 WP-09 (v5.0 plan 8.1): the frozen contract -- CLI docs match the
parser, exit codes, finding states, schema versions, report minimum
fields and reproduction environment records."""

import argparse
import asyncio
import json
from pathlib import Path

import httpx
import pytest

from cli import build_parser, main
from core.contract import (
    EXIT_CODES,
    FINDING_STATES,
    REQUIRED_REPORT_FIELDS,
    SCHEMA_VERSIONS,
    check_schema_version,
    execution_environment,
)
from core.models import FindingStatus
from core.paths import RESULTS_DIR_ENV
from docs.gen_cli_reference import render
from reporting.integrity import build_run_manifest
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore
from validation.workflow import build_scan_artifact, run_validate, write_validation_report

CLI_DOC = Path("docs/CLI.md").read_text(encoding="utf-8")


def _subparsers() -> dict[str, argparse.ArgumentParser]:
    parser = build_parser()
    return next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction)).choices


def test_cli_reference_is_up_to_date(monkeypatch) -> None:
    # Defaults must render as the real relative results path, not the
    # test-session temp dir conftest.py points BUGBOUNTY_RESULTS_DIR at.
    monkeypatch.delenv(RESULTS_DIR_ENV, raising=False)
    assert render() == CLI_DOC, "run: python docs/gen_cli_reference.py"


def test_every_command_and_option_is_documented() -> None:
    for name, subparser in _subparsers().items():
        assert f"### `{name}`" in CLI_DOC
        for action in subparser._actions:
            if isinstance(action, argparse._HelpAction):
                continue
            for flag in action.option_strings:
                assert flag in CLI_DOC, f"{name} {flag} missing from docs/CLI.md"


def test_exit_codes_are_documented() -> None:
    for code in EXIT_CODES:
        assert f"| {code} |" in CLI_DOC


def test_finding_states_match_the_enum() -> None:
    assert set(FINDING_STATES) == {status.value for status in FindingStatus}
    assert {"candidate", "needs_review", "confirmed", "rejected"} <= set(FINDING_STATES)


def test_scope_schema_version_is_enforced() -> None:
    PolicyEngine({"schema_version": 1, "scope": {}})
    PolicyEngine({"scope": {}})  # absent = 1, backward compatible
    with pytest.raises(ValueError, match="scope_policy"):
        PolicyEngine({"schema_version": 2, "scope": {}})
    with pytest.raises(ValueError):
        check_schema_version("scan_artifact", 9)


def test_input_errors_exit_3_without_traceback(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["validate", "--artifact", str(tmp_path / "missing.json"), "--base-url", "https://x.example"]) == 3
    err = json.loads(capsys.readouterr().err)
    assert err["error"] == "FileNotFoundError"
    bad_scope = tmp_path / "scope.yaml"
    bad_scope.write_text("schema_version: 7\n", encoding="utf-8")
    assert main(["validate-scope", "--scope", str(bad_scope), "--url", "https://x.example"]) == 3


def test_scope_denied_is_exit_2() -> None:
    assert main(["validate-scope", "--url", "https://not-in-scope.example"]) == 2


def test_report_has_required_fields_and_manifest_is_versioned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    store = SQLiteStore(tmp_path / "v.sqlite")
    policy = PolicyEngine({"scope": {"domains": ["in.example.com"]}, "testing": {"automated_scanning": True}})
    fixture = Path(__file__).resolve().parent / "fixtures/source/rest_api_app"
    result = asyncio.run(
        run_validate(build_scan_artifact(fixture), "https://in.example.com", policy, store,
                     transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    )
    write_validation_report(store, result["run_id"], tmp_path / "r")
    finding_id = result["findings"][0]["finding_id"]
    report = json.loads((tmp_path / "r" / f"{finding_id}.json").read_text(encoding="utf-8"))
    assert set(REQUIRED_REPORT_FIELDS) <= set(report)
    assert report["schema_version"] == SCHEMA_VERSIONS["validation_report"]
    assert build_run_manifest(store, result["run_id"]).to_dict()["schema_version"] == SCHEMA_VERSIONS["evidence_manifest"]


def test_reproduce_records_execution_environment(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "s.sqlite"
    assert main(["sample-run", "--db", str(db)]) == 0
    run_id = json.loads(capsys.readouterr().out)["run_id"]
    finding = next(f for f in SQLiteStore(db).list_findings([run_id]) if f.status.value == "confirmed")
    assert main(["reproduce", finding.id, "--db", str(db)]) == 0
    environment = json.loads(capsys.readouterr().out)["environment"]
    assert {"python", "platform", "package_version", "contract_version", "target_kind", "testcases_sha256", "scope_sha256"} <= set(environment)
    assert environment["target_kind"] == "fake-llm"


def test_execution_environment_includes_extra_fields() -> None:
    assert execution_environment(attempts=3)["attempts"] == 3


def test_package_version_comes_from_the_source_tree() -> None:
    from core.contract import package_version

    import tomllib

    expected = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    assert package_version() == expected
