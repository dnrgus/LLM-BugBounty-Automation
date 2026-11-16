"""Run the local scanner as an ARTEX worker tool and emit compact graph facts."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(url: str, scope: Path | None, output: Path, profile: str, timeout: int) -> dict:
    command = [sys.executable, str(ROOT / "main.py"), "scan", url, "--profile", profile,
               "--output", str(output), "--quiet"]
    if scope is not None:
        command.extend(["--scope", str(scope.resolve())])
    try:
        process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                 timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"schema": "artex-bridge/v1", "ok": False, "error": "scan_timeout"}
    if process.returncode:
        return {"schema": "artex-bridge/v1", "ok": False, "error": "scan_failed",
                "exit_code": process.returncode, "detail": process.stderr[-2000:]}
    try:
        scan = json.loads(process.stdout)
        results_dir = Path(scan["results"]["results_dir"])
        summary = json.loads((results_dir / "summary.json").read_text(encoding="utf-8"))
    except (ValueError, KeyError, TypeError, OSError) as exc:
        return {"schema": "artex-bridge/v1", "ok": False, "error": "invalid_scan_output",
                "detail": type(exc).__name__}
    if scan.get("mode") != "live" or summary.get("target") != url:
        return {"schema": "artex-bridge/v1", "ok": False, "error": "unexpected_scan_target"}

    findings = []
    for item in summary.get("findings", []):
        status = item.get("status")
        findings.append({
            "id": item.get("id"), "title": item.get("title"),
            "status": status, "severity": item.get("severity"),
            "endpoint": item.get("endpoint"), "source_tool": item.get("source_tool"),
            "graph_kind": "finding" if status == "confirmed" else "candidate",
            "report_path": str(results_dir / item["path"] / "report.md"),
        })
    discovery = scan.get("discovery") or {}
    return {
        "schema": "artex-bridge/v1", "ok": True, "target": url,
        "run_id": summary.get("run_id"), "results_dir": str(results_dir),
        "assets": (discovery.get("attack_surface") or {}).get("items", []),
        "findings": findings,
        "discovery_errors": discovery.get("errors", []),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ARTEX worker adapter for bugbounty scan")
    parser.add_argument("url")
    parser.add_argument("--scope", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=("quick", "llm", "agent", "rag", "web", "full"), default="quick")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args(argv)
    result = run(args.url, args.scope, args.output.resolve(), args.profile, args.timeout)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
