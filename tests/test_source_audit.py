import json
from pathlib import Path

from source.audit import audit_source
from source.ingestion import ingest_source
from source.routes import extract_routes

FIXTURE = Path("tests/fixtures/source/sample_app")


def test_ingest_source_detects_language_and_framework() -> None:
    result = ingest_source(FIXTURE)
    assert result.primary_language == "python"
    assert result.language_counts == {"python": 1}
    assert "flask" in result.frameworks
    assert len(result.files) == 1


def test_ingest_source_respects_max_files_budget(tmp_path: Path) -> None:
    for i in range(10):
        (tmp_path / f"file_{i}.py").write_text("x = 1\n", encoding="utf-8")
    result = ingest_source(tmp_path, max_files=3)
    assert len(result.files) == 3


def test_extract_routes_finds_flask_endpoints() -> None:
    result = ingest_source(FIXTURE)
    routes = extract_routes(result.files)
    locations = {(item.metadata["method"], item.location) for item in routes}
    assert ("ROUTE", "/api/chat") in locations
    assert ("ROUTE", "/api/admin/run") in locations


def test_extract_routes_does_not_double_count_an_explicit_method_decorator() -> None:
    # @app.get(...)/@app.post(...) is Flask/FastAPI decorator syntax, but its
    # text also looks like an Express.js app.get(...) call -- must be
    # detected once, not once per matching pattern.
    result = ingest_source(Path("tests/fixtures/source/hybrid_app"))
    routes = extract_routes(result.files)
    about_routes = [item for item in routes if item.location == "/about"]
    assert len(about_routes) == 1
    assert about_routes[0].metadata["method"] == "GET"
    assert about_routes[0].metadata["framework"] == "flask_fastapi"


def test_audit_source_produces_expected_attack_surface_shape() -> None:
    result = audit_source(FIXTURE)
    assert result["primary_language"] == "python"
    assert result["frameworks"] == ["flask"]
    assert result["files_scanned"] == 1

    surface = result["attack_surface"]
    assert surface["by_asset_type"] == {"endpoint": 2, "parameter": 2, "function": 1, "secret": 2, "llm": 1}
    assert surface["total"] == 8


def test_audit_source_flags_dangerous_sink_and_llm_integration() -> None:
    result = audit_source(FIXTURE)
    items = result["attack_surface"]["items"]
    sink_types = {item["metadata"]["sink_type"] for item in items if item["asset_type"] == "function"}
    assert "os_command" in sink_types
    llm_items = [item for item in items if item["asset_type"] == "llm"]
    assert len(llm_items) == 1
    assert llm_items[0]["metadata"]["llm_detected"] is True


def test_audit_source_never_leaks_the_raw_secret_value() -> None:
    result = audit_source(FIXTURE)
    dump = json.dumps(result)
    assert "AKIAABCDEFGHIJKLMNOP" not in dump
    secret_items = [item for item in result["attack_surface"]["items"] if item["asset_type"] == "secret"]
    assert {item["metadata"]["secret_type"] for item in secret_items} == {"aws_access_key", "generic_api_key"}


def test_audit_source_handles_missing_directory_gracefully(tmp_path: Path) -> None:
    result = audit_source(tmp_path / "does-not-exist")
    assert result["files_scanned"] == 0
    assert result["attack_surface"]["total"] == 0
