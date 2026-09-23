"""P4.2-D JS/TS dataflow tracing (roadmap v4.2.0 Source Intelligence
Expansion) -- the JS/TS equivalent of tests/test_dataflow_python.py."""

from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")

from source.dataflow.javascript import trace_dataflow  # noqa: E402


def test_traces_request_body_reaching_child_process_exec() -> None:
    text = (
        "function handler(req, res) {\n"
        "  const cmd = req.body.cmd;\n"
        "  child_process.exec(cmd);\n"
        "}\n"
    )
    edges = trace_dataflow(Path("app.js"), text)
    assert len(edges) == 1
    assert edges[0].sink == "os_command"
    assert edges[0].source == "request"


def test_no_edge_when_sink_argument_is_not_tainted() -> None:
    text = "function handler(req, res) {\n  child_process.exec('ls -la');\n}\n"
    edges = trace_dataflow(Path("app.js"), text)
    assert edges == []


def test_direct_request_access_in_sink_call_is_traced_without_intermediate_variable() -> None:
    text = "function handler(req, res) {\n  eval(req.query.expr);\n}\n"
    edges = trace_dataflow(Path("app.js"), text)
    assert len(edges) == 1
    assert edges[0].sink == "code_execution"


def test_taint_propagates_through_template_string() -> None:
    text = (
        "function handler(req, res) {\n"
        "  const name = req.body.name;\n"
        "  const query = `SELECT * FROM users WHERE name = '${name}'`;\n"
        "  db.query(query);\n"
        "}\n"
    )
    edges = trace_dataflow(Path("app.js"), text)
    assert len(edges) == 1
    assert edges[0].sink == "sql_injection"


def test_taint_propagates_through_array_literal_argument() -> None:
    text = (
        "function handler(req, res) {\n"
        "  const content = req.body.message;\n"
        "  client.messages.create({ messages: [content] });\n"
        "}\n"
    )
    edges = trace_dataflow(Path("app.js"), text)
    assert len(edges) == 1
    assert edges[0].sink == "prompt_injection_sink"


def test_reassigning_a_tainted_variable_to_a_safe_value_clears_taint() -> None:
    text = (
        "function handler(req, res) {\n"
        "  var cmd = req.body.cmd;\n"
        "  cmd = 'safe-value';\n"
        "  child_process.exec(cmd);\n"
        "}\n"
    )
    edges = trace_dataflow(Path("app.js"), text)
    assert edges == []


def test_taint_does_not_leak_into_an_unrelated_function_scope() -> None:
    text = (
        "function handler(req, res) {\n"
        "  const cmd = req.body.cmd;\n"
        "}\n"
        "function other() {\n"
        "  child_process.exec(cmd);\n"
        "}\n"
    )
    edges = trace_dataflow(Path("app.js"), text)
    assert edges == []


def test_typescript_file_is_also_traced() -> None:
    text = (
        "function handler(req: any, res: any) {\n"
        "  const cmd: string = req.body.cmd;\n"
        "  child_process.exec(cmd);\n"
        "}\n"
    )
    edges = trace_dataflow(Path("app.ts"), text)
    assert len(edges) == 1


def test_syntax_error_returns_no_edges_instead_of_raising() -> None:
    edges = trace_dataflow(Path("broken.js"), "function( { { { not valid js")
    assert edges == []


def test_edges_are_deduplicated() -> None:
    text = (
        "function handler(req, res) {\n"
        "  const cmd = req.body.cmd;\n"
        "  if (true) {\n"
        "    child_process.exec(cmd);\n"
        "  }\n"
        "}\n"
    )
    edges = trace_dataflow(Path("app.js"), text)
    assert len(edges) == 1
