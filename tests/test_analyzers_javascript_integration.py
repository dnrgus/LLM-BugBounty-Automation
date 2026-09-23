"""P4.2-D end-to-end integration (roadmap v4.2.0 Source Intelligence
Expansion): proves source/analyzers.py's registry-driven dispatch
(P4.2-A) actually reaches the new JS/TS dataflow/auth backends for
real .js/.ts SourceFile input, not just that the backends work in
isolation.
"""

from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")

from source.analyzers import analyze_files  # noqa: E402
from source.ingestion import SourceFile  # noqa: E402
from source.routes import extract_routes  # noqa: E402


def test_js_file_produces_dataflow_items_through_analyze_files(tmp_path: Path) -> None:
    source_path = tmp_path / "app.js"
    source_path.write_text(
        "function handler(req, res) {\n  const cmd = req.body.cmd;\n  child_process.exec(cmd);\n}\n",
        encoding="utf-8",
    )
    items = analyze_files([SourceFile(path=source_path, language="javascript")])
    dataflow_items = [item for item in items if item.asset_type == "dataflow"]
    assert len(dataflow_items) == 1
    assert dataflow_items[0].metadata["sink_type"] == "os_command"


def test_ts_controller_produces_auth_items_through_analyze_files(tmp_path: Path) -> None:
    source_path = tmp_path / "cats.controller.ts"
    source_path.write_text(
        "@Controller('cats')\nexport class CatsController {\n  @Get()\n  findAll(): string { return ''; }\n}\n",
        encoding="utf-8",
    )
    routes = extract_routes([SourceFile(path=source_path, language="typescript")])
    assert routes and routes[0].metadata["handler"] == "findAll"

    items = analyze_files([SourceFile(path=source_path, language="typescript")], routes=routes)
    auth_items = [item for item in items if item.asset_type == "auth"]
    assert len(auth_items) == 1
    assert auth_items[0].metadata["detected"] is False


def test_python_file_is_unaffected_by_the_javascript_registration(tmp_path: Path) -> None:
    source_path = tmp_path / "app.py"
    source_path.write_text(
        "from flask import request\n\ndef handler():\n    cmd = request.args.get('cmd')\n    os.system(cmd)\n",
        encoding="utf-8",
    )
    items = analyze_files([SourceFile(path=source_path, language="python")])
    dataflow_items = [item for item in items if item.asset_type == "dataflow"]
    assert len(dataflow_items) == 1
    assert dataflow_items[0].metadata["sink_type"] == "os_command"
