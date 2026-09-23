from __future__ import annotations

# P3.2-3 (roadmap v3.2.0 Source Intelligence): the dangerous-call
# categories the roadmap names explicitly -- SQL/command/file/template/
# HTTP/LLM-prompt -- keyed by a call's *dotted* callee name (as written;
# see source/dataflow/python.py's _dotted_name), matched by suffix so an
# import alias (`from os import system as sys_call`) doesn't need special
# handling for the common `module.func` case.
_EXACT_SINKS = {
    "eval": "code_execution",
    "exec": "code_execution",
    "os.system": "os_command",
    "subprocess.run": "os_command",
    "subprocess.call": "os_command",
    "subprocess.Popen": "os_command",
    "subprocess.check_output": "os_command",
    "pickle.loads": "deserialization",
    "pickle.load": "deserialization",
    "yaml.load": "deserialization",
    "render_template_string": "template_injection",
    "open": "file_access",
    # P4.2-D (roadmap v4.2.0 Source Intelligence Expansion): JS/TS
    # equivalents, keyed the same way (dotted callee name as written).
    "Function": "code_execution",
    "child_process.exec": "os_command",
    "child_process.execSync": "os_command",
    "child_process.spawn": "os_command",
    "fs.readFileSync": "file_access",
    "fs.readFile": "file_access",
    "res.render": "template_injection",
}

_SQL_METHOD_NAMES = {"execute", "query"}

_HTTP_CALL_SUFFIXES = (
    "requests.get", "requests.post", "requests.put", "requests.delete", "requests.patch",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.patch",
    "axios.get", "axios.post", "axios.put", "axios.delete", "axios.patch",
)

_LLM_CALL_SUFFIXES = (
    "ChatCompletion.create",
    "chat.completions.create",
    "messages.create",
    "generate_content",
)


def sink_for_call(dotted_name: str) -> str | None:
    """Classifies a call's dotted callee name into a sink category, or
    None if it isn't one of the categories this project tracks."""
    if dotted_name in _EXACT_SINKS:
        return _EXACT_SINKS[dotted_name]
    method = dotted_name.rsplit(".", 1)[-1]
    if method in _SQL_METHOD_NAMES:
        return "sql_injection"
    if any(dotted_name.endswith(suffix) for suffix in _HTTP_CALL_SUFFIXES):
        return "ssrf"
    if any(dotted_name.endswith(suffix) for suffix in _LLM_CALL_SUFFIXES):
        return "prompt_injection_sink"
    return None
