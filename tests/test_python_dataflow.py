"""P3.2-3 Source/Sink + Lightweight Dataflow (roadmap v3.2.0 Source Intelligence).

positive/negative dataflow corpus per the roadmap's own required test
list, plus a precision check (a dangerous sink with no traced tainted
argument must not be flagged) and a one-hop interprocedural case.
"""

from pathlib import Path

from source.dataflow.python import trace_dataflow

_PATH = Path("app.py")


def _sinks(text: str) -> set[str]:
    return {edge.sink for edge in trace_dataflow(_PATH, text)}


def test_direct_tainted_argument_reaches_os_command_sink() -> None:
    text = "import os\nos.system(request.args.get('cmd'))\n"
    assert _sinks(text) == {"os_command"}


def test_taint_propagates_through_an_intermediate_assignment() -> None:
    text = "import os\ncmd = request.args.get('cmd')\nos.system(cmd)\n"
    edges = trace_dataflow(_PATH, text)
    assert len(edges) == 1
    assert edges[0].sink == "os_command"
    assert edges[0].line == 3
    assert edges[0].file == str(_PATH)


def test_negative_control_hardcoded_argument_is_not_flagged() -> None:
    text = "import os\nos.system('ls -la')\n"
    assert trace_dataflow(_PATH, text) == []


def test_negative_control_reassignment_to_a_safe_value_clears_prior_taint() -> None:
    text = "import os\nx = request.args.get('a')\nx = 'safe'\nos.system(x)\n"
    assert trace_dataflow(_PATH, text) == []


def test_sql_injection_sink_via_f_string() -> None:
    text = "def handler(cursor):\n    uid = request.args.get('id')\n    cursor.execute(f'SELECT * FROM t WHERE id={uid}')\n"
    assert _sinks(text) == {"sql_injection"}


def test_sql_sink_with_no_tainted_argument_is_not_flagged() -> None:
    text = "def handler(cursor):\n    cursor.execute('SELECT * FROM t')\n"
    assert trace_dataflow(_PATH, text) == []


def test_file_access_sink() -> None:
    text = "path = request.args.get('path')\nopen(path)\n"
    assert _sinks(text) == {"file_access"}


def test_ssrf_sink_via_requests_get() -> None:
    text = "import requests\nurl = request.args.get('url')\nrequests.get(url)\n"
    assert _sinks(text) == {"ssrf"}


def test_llm_prompt_injection_sink_through_a_messages_list_literal() -> None:
    text = (
        "import openai\n"
        "message = request.json.get('message')\n"
        "openai.ChatCompletion.create(model='gpt-4', messages=[{'role': 'user', 'content': message}])\n"
    )
    assert _sinks(text) == {"prompt_injection_sink"}


def test_one_hop_interprocedural_taint_propagation() -> None:
    text = (
        "import os\n"
        "def handler():\n"
        "    cmd = request.args.get('cmd')\n"
        "    run(cmd)\n\n"
        "def run(c):\n"
        "    os.system(c)\n"
    )
    edges = trace_dataflow(_PATH, text)
    assert len(edges) == 1
    assert edges[0].sink == "os_command"
    assert edges[0].line == 7  # the os.system(c) line inside run(), not the call site


def test_interprocedural_propagation_does_not_taint_unrelated_calls_to_the_same_function() -> None:
    # run() is also called with a hardcoded value elsewhere -- that call
    # site itself must not create a false edge; the finding comes from
    # run()'s own tainted-parameter re-analysis.
    text = (
        "import os\n"
        "def run(c):\n"
        "    os.system(c)\n\n"
        "def handler():\n"
        "    cmd = request.args.get('cmd')\n"
        "    run(cmd)\n\n"
        "def other():\n"
        "    run('ls')\n"
    )
    edges = trace_dataflow(_PATH, text)
    assert len(edges) == 1


def test_syntax_error_returns_no_edges_instead_of_raising() -> None:
    assert trace_dataflow(_PATH, "def broken(:\n") == []


def test_non_python_style_call_without_a_source_or_sink_is_ignored() -> None:
    text = "def handler():\n    x = compute()\n    log(x)\n"
    assert trace_dataflow(_PATH, text) == []
