"""P4.6 WP-04 (v5.0 plan 6.1/6.4): Python route -> service -> sink
propagation across files, pinned as regression, plus graph caps."""

from pathlib import Path

from source.audit import audit_source, collect_source_items
from source.interprocedural.python import trace_interprocedural
from source.sinks.python import sink_family

LAYERED = Path("tests/fixtures/source/layered_flask_app")
FASTAPI_CHAIN = Path("tests/fixtures/source/fastapi_chain")


def _edges(root: Path, **caps):
    return trace_interprocedural(root, sorted(root.rglob("*.py")), **caps)


def _by_entry(edges):
    return {edge.entry: edge for edge in edges}


def test_layered_flask_chains_are_traced_across_files() -> None:
    edges, stats = _edges(LAYERED)
    by_entry = _by_entry(edges)

    sql = by_entry["app.routes:search_notes"]
    assert sql.sink == "sql_injection" and sql.sink_family == "sql"
    assert sql.call_path == ("app.routes:search_notes", "app.services.notes:find_notes", "app.db.repo:run_query")
    assert sql.file.endswith("app/db/repo.py")

    assert by_entry["app.routes:preview_note"].sink_family == "template"
    command = by_entry["app.routes:export_report"]
    assert command.sink_family == "command"
    assert command.hops == 2  # route -> reports.export (module alias) -> _archive
    assert stats.truncated == []


def test_static_argument_route_produces_no_edge() -> None:
    edges, _ = _edges(LAYERED)
    assert "app.routes:health" not in _by_entry(edges)


def test_fastapi_route_params_are_sources_but_depends_params_are_not() -> None:
    edges, _ = _edges(FASTAPI_CHAIN)
    by_entry = _by_entry(edges)
    assert by_entry["main:preview"].sink_family == "url_fetch"
    assert "main:depends_only" not in by_entry


def test_recursion_terminates_and_still_reports_sink() -> None:
    edges, _ = _edges(FASTAPI_CHAIN)
    assert _by_entry(edges)["main:loop"].sink == "os_command"


def test_method_calls_are_an_explicit_cut_not_a_guess() -> None:
    edges, _ = _edges(FASTAPI_CHAIN)
    assert "main:method_call" not in _by_entry(edges)


def test_max_depth_cap_truncates_long_chains_gracefully() -> None:
    edges, stats = _edges(LAYERED, max_depth=1)
    assert "app.routes:search_notes" not in _by_entry(edges)  # needs 2 hops
    assert "app.routes:preview_note" in _by_entry(edges)  # 1 hop still fine
    assert "max_depth" in stats.truncated


def test_node_and_time_caps_stop_expansion_without_raising() -> None:
    _, node_stats = _edges(LAYERED, max_nodes=1)
    assert "max_nodes" in node_stats.truncated
    assert node_stats.analyses <= 1
    _, time_stats = _edges(LAYERED, time_budget_s=0.0)
    assert "time_budget" in time_stats.truncated


def test_audit_items_carry_route_auth_and_call_path_metadata() -> None:
    _, items = collect_source_items(LAYERED)
    dataflow = {item.metadata["entry"]: item for item in items if item.asset_type == "dataflow" and "entry" in item.metadata}
    sql = dataflow["app.routes:search_notes"]
    assert sql.metadata["route"] == "GET /notes/search"
    assert sql.metadata["auth_guard_detected"] is False
    assert sql.metadata["hops"] == 2
    assert sql.confidence < 0.85  # longer chains decay


def test_single_file_edges_are_not_duplicated_by_interprocedural_pass() -> None:
    _, items = collect_source_items("tests/fixtures/source/sample_app")
    keys = [(item.metadata["line"], item.metadata["sink_type"]) for item in items if item.asset_type == "dataflow"]
    assert len(keys) == len(set(keys))


def test_audit_reports_interprocedural_stats() -> None:
    assert audit_source(LAYERED)["interprocedural"]["functions"] >= 8


def test_sink_family_mapping() -> None:
    assert sink_family("os_command") == sink_family("code_execution") == "command"
    assert sink_family("ssrf") == "url_fetch"
    assert sink_family("unknown") == "other"
