"""Run the local scanner as an ARTEX worker tool and emit compact graph facts."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


def _artex_assets(items: list[dict]) -> list[dict]:
    """Only observed HTTP endpoints have ARTEX's required URL and method."""
    assets: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        if item.get("asset_type") != "endpoint":
            continue
        url = item.get("location")
        method = (item.get("metadata") or {}).get("method")
        if not isinstance(url, str) or not isinstance(method, str):
            continue
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
            continue
        if urlsplit(url).scheme not in {"http", "https"} or not urlsplit(url).netloc:
            continue
        key = (method, url)
        if key not in seen:
            assets.append({"type": "endpoint", "url": url, "method": method})
            seen.add(key)
    return assets


def _finding_evidence(folder: Path) -> dict | None:
    """Carry the actual sanitized evidence, with a digest of the complete file."""
    path = folder / "evidence.json"
    try:
        raw = path.read_bytes()
        parsed = json.loads(raw)
    except (OSError, ValueError):
        return None
    if not isinstance(parsed, dict) or not any(parsed.get(key) for key in
                                                  ("response", "steps", "observations", "redacted_secret", "raw", "reproduction")):
        return None
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def run(url: str, scope: Path | None, output: Path, profile: str, timeout: int,
        target_config: Path | None = None) -> dict:
    command = [sys.executable, str(ROOT / "main.py"), "scan", url, "--profile", profile,
               "--output", str(output), "--quiet"]
    if scope is not None:
        command.extend(["--scope", str(scope.resolve())])
    if target_config is not None:
        command.extend(["--pack-target", "openai", "--pack-target-config", str(target_config.resolve())])
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
        folder = (results_dir / item["path"]).resolve()
        if not folder.is_relative_to(results_dir.resolve()):
            return {"schema": "artex-bridge/v1", "ok": False,
                    "error": "invalid_finding_path"}
        evidence = _finding_evidence(folder)
        findings.append({
            "id": item.get("id"), "title": item.get("title"),
            "status": status, "severity": item.get("severity"),
            "endpoint": item.get("endpoint"), "source_tool": item.get("source_tool"),
            "graph_kind": "finding" if status == "confirmed" and evidence else "candidate",
            "report_path": str(folder / "report.md"),
            "evidence": evidence,
        })
    discovery = scan.get("discovery") or {}
    coverage = [
        {"pack_id": selection.get("pack_id"), "selected": selection.get("selected"),
         "reason": selection.get("reason")}
        for selection in scan.get("pack_selection", [])
    ]
    executions = [
        {"pack_id": execution.get("pack_id"), "tool_id": execution.get("tool_id"),
         "status": execution.get("status"), "detail": execution.get("detail")}
        for execution in scan.get("pack_runs", [])
    ]
    assets = (discovery.get("attack_surface") or {}).get("items", [])
    return {
        "schema": "artex-bridge/v1", "ok": True, "target": url,
        "run_id": summary.get("run_id"), "results_dir": str(results_dir),
        "assets": assets, "artex_assets": _artex_assets(assets),
        "findings": findings,
        "pack_selection": coverage, "pack_executions": executions,
        "discovery_errors": discovery.get("errors", []),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ARTEX worker adapter for bugbounty scan")
    parser.add_argument("url")
    parser.add_argument("--scope", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=("quick", "llm", "agent", "rag", "web", "full"), default="quick")
    parser.add_argument("--target-config", type=Path,
                        help="Target adapter YAML for running LLM/RAG/Agent testcase packs")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args(argv)
    result = run(args.url, args.scope, args.output.resolve(), args.profile, args.timeout,
                 args.target_config)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
