"""P3.2-1 Parser Abstraction + Python AST (roadmap v3.2.0 Source Intelligence)."""

from pathlib import Path

from source.parsers.base import merge_results
from source.parsers.python import PythonASTParser

_parser = PythonASTParser()


def test_parses_flask_route_with_explicit_methods_kwarg() -> None:
    text = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/api/chat', methods=['POST'])\n"
        "def chat():\n"
        "    return 'ok'\n"
    )
    result = _parser.parse_file(Path("app.py"), text)
    assert not result.errors
    assert len(result.routes) == 1
    route = result.routes[0]
    assert route.method == "POST"
    assert route.path == "/api/chat"
    assert route.handler == "chat"
    assert route.framework == "flask_fastapi"
    assert route.line == 4


def test_parses_fastapi_get_decorator() -> None:
    text = "@app.get('/health')\nasync def health():\n    return 'ok'\n"
    result = _parser.parse_file(Path("app.py"), text)
    assert len(result.routes) == 1
    assert result.routes[0].method == "GET"
    assert result.routes[0].handler == "health"


def test_parses_api_route_with_multiple_methods() -> None:
    text = "@app.api_route('/both', methods=['GET', 'POST'])\ndef both():\n    return 'ok'\n"
    result = _parser.parse_file(Path("app.py"), text)
    assert result.routes[0].method == "GET|POST"


def test_bare_route_decorator_without_methods_defaults_to_route() -> None:
    text = "@app.route('/legacy')\ndef legacy():\n    return 'ok'\n"
    result = _parser.parse_file(Path("app.py"), text)
    assert result.routes[0].method == "ROUTE"


def test_non_route_decorators_and_calls_are_ignored_for_routes_but_calls_are_recorded() -> None:
    text = (
        "import os\n\n"
        "@app.middleware('http')\n"
        "def mw():\n"
        "    os.system('id')\n"
        "    return None\n"
    )
    result = _parser.parse_file(Path("app.py"), text)
    assert result.routes == []
    call_names = [call.name for call in result.calls]
    assert "os.system" in call_names
    system_call = next(call for call in result.calls if call.name == "os.system")
    assert system_call.enclosing_function == "mw"


def test_syntax_error_is_reported_as_a_parser_error_instead_of_raising() -> None:
    result = _parser.parse_file(Path("broken.py"), "def app.route('/x'\n    this is not valid python\n")
    assert result.routes == []
    assert result.errors
    assert "broken.py" in result.errors[0]


def test_merge_results_combines_multiple_files() -> None:
    a = _parser.parse_file(Path("a.py"), "@app.get('/a')\ndef a():\n    return 1\n")
    b = _parser.parse_file(Path("b.py"), "@app.post('/b')\ndef b():\n    return 2\n")
    merged = merge_results([a, b])
    assert merged.language == "python"
    assert {route.path for route in merged.routes} == {"/a", "/b"}


def test_merge_results_on_empty_list_returns_unknown_language() -> None:
    merged = merge_results([])
    assert merged.language == "unknown"
    assert merged.routes == []
