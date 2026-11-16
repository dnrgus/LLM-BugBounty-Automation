import asyncio
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx

from integrations.artex_verify import verify
from integrations.artex_tool_spec import build_verify_spec
from scope.policy import PolicyEngine


def _candidate(**changes):
    value = {
        "vulnerability_type": "response_differential",
        "target_url": "https://ai.example.com/proof",
        "method": "GET",
        "auth_context": "anonymous",
        "prerequisites": [],
        "success_criteria": {"type": "body_contains", "value": "private-marker",
                             "control_url": "https://ai.example.com/control"},
        "observed_evidence": {"request": "GET /proof", "response": "private-marker"},
    }
    value.update(changes)
    return value


def _policy(max_requests=3):
    return PolicyEngine({"scope": {"domains": ["ai.example.com"]},
                         "testing": {"automated_scanning": True},
                         "limits": {"max_requests_per_run": max_requests}})


def test_verify_confirms_replay_with_control_and_evidence(tmp_path):
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, text="private-marker" if request.url.path == "/proof" else "public")

    result = asyncio.run(verify(_candidate(), _policy(), tmp_path,
                                transport=httpx.MockTransport(handler)))
    assert result["status"] == "confirmed"
    assert calls == ["/control", "/proof", "/proof"]
    evidence = result["evidence"]
    assert evidence["sha256"]
    assert json.loads(open(evidence["path"], encoding="utf-8").read())["status"] == "confirmed"
    assert "Evidence SHA-256" in open(result["report_path"], encoding="utf-8").read()


def test_verify_blocks_out_of_scope_before_network(tmp_path):
    result = asyncio.run(verify(_candidate(target_url="https://other.example/proof"), _policy(), tmp_path,
                                transport=httpx.MockTransport(lambda request: (_ for _ in ()).throw(AssertionError("sent")))))
    assert result["status"] == "unavailable"


def test_verify_reports_missing_auth_and_unsupported_type(tmp_path):
    policy = _policy()
    assert asyncio.run(verify(_candidate(auth_context="owner"), policy, tmp_path))["status"] == "unavailable"
    result = asyncio.run(verify(_candidate(vulnerability_type="sqli"), policy, tmp_path))
    assert result["status"] == "unavailable"
    assert "unsupported" in result["reason"]
    needs_steps = asyncio.run(verify(_candidate(prerequisites=["first login as owner"]), policy, tmp_path))
    assert needs_steps["status"] == "unavailable"
    assert "prerequisite" in needs_steps["reason"]


def test_verify_auth_failure_and_request_budget(tmp_path):
    denied = asyncio.run(verify(_candidate(), _policy(), tmp_path,
                                transport=httpx.MockTransport(lambda request: httpx.Response(401))))
    assert denied["status"] == "unavailable"
    limited = asyncio.run(verify(_candidate(), _policy(1), tmp_path,
                                 transport=httpx.MockTransport(lambda request: httpx.Response(200, text="public"))))
    assert limited["status"] == "unavailable"
    assert "budget" in limited["reason"]


def test_generated_worker_verify_script_against_local_target(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"private-marker" if self.path == "/proof" else b"public"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        root = Path(__file__).resolve().parents[1]
        scope = tmp_path / "scope.yaml"
        scope.write_text("scope:\n  domains: [127.0.0.1]\ntesting:\n  automated_scanning: true\nlimits:\n  max_requests_per_run: 3\n", encoding="utf-8")
        spec = build_verify_spec(root, scope, Path(sys.executable))
        compile(spec["exec"]["code"], "<worker-tool>", "exec")
        base = f"http://127.0.0.1:{server.server_port}"
        candidate = _candidate(target_url=base + "/proof",
                               success_criteria={"type": "body_contains", "value": "private-marker",
                                                 "control_url": base + "/control"})
        process = subprocess.run([sys.executable, "-c", spec["exec"]["code"]],
                                 input=json.dumps(candidate), text=True, capture_output=True, timeout=15)
        assert process.returncode == 0, process.stderr
        result = json.loads(process.stdout)
        assert result["status"] == "confirmed"
        assert Path(result["evidence"]["path"]).exists()
    finally:
        server.shutdown()
        thread.join(timeout=2)
