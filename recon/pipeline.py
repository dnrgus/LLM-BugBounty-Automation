from __future__ import annotations

from dataclasses import asdict, replace
from pathlib import Path

from adapters.discovery.ffuf import FfufAdapter
from adapters.discovery.katana import KatanaAdapter
from adapters.recon.httpx import HttpxAdapter
from adapters.recon.subfinder import SubfinderAdapter
from core.models import Asset, Endpoint
from recon.classifier import classify_endpoint
from scope.policy import PolicyEngine
from storage.sqlite import SQLiteStore

_ENDPOINT_ADAPTERS = (
    ("httpx_input", HttpxAdapter),
    ("katana_input", KatanaAdapter),
    ("ffuf_input", FfufAdapter),
)


def build_asset_map(
    policy: PolicyEngine,
    store: SQLiteStore,
    run_id: str,
    target_id: str,
    subfinder_input: Path | str | None = None,
    httpx_input: Path | str | None = None,
    katana_input: Path | str | None = None,
    ffuf_input: Path | str | None = None,
) -> dict[str, object]:
    store.initialize()

    inputs = {"httpx_input": httpx_input, "katana_input": katana_input, "ffuf_input": ffuf_input}

    assets: list[Asset] = []
    if subfinder_input is not None:
        for asset in SubfinderAdapter().parse_file(subfinder_input, run_id=run_id, target_id=target_id):
            decision = policy.validate_domain(asset.domain)
            assets.append(replace(asset, in_scope=decision.allowed))

    endpoints: list[Endpoint] = []
    for input_key, adapter_cls in _ENDPOINT_ADAPTERS:
        path = inputs[input_key]
        if path is None:
            continue
        for endpoint in adapter_cls().parse_file(path, run_id=run_id, target_id=target_id):
            decision = policy.validate_url(endpoint.url)
            endpoints.append(
                replace(endpoint, in_scope=decision.allowed, classification=classify_endpoint(endpoint))
            )

    for asset in assets:
        store.insert_asset(asset)
    for endpoint in endpoints:
        store.insert_endpoint(endpoint)

    by_source: dict[str, int] = {}
    by_classification: dict[str, int] = {}
    for endpoint in endpoints:
        by_source[endpoint.source] = by_source.get(endpoint.source, 0) + 1
        by_classification[endpoint.classification] = by_classification.get(endpoint.classification, 0) + 1

    return {
        "run_id": run_id,
        "target_id": target_id,
        "assets": {
            "total": len(assets),
            "in_scope": sum(1 for asset in assets if asset.in_scope),
            "out_of_scope": sum(1 for asset in assets if not asset.in_scope),
            "items": [asdict(asset) for asset in assets],
        },
        "endpoints": {
            "total": len(endpoints),
            "in_scope": sum(1 for endpoint in endpoints if endpoint.in_scope),
            "out_of_scope": sum(1 for endpoint in endpoints if not endpoint.in_scope),
            "by_source": by_source,
            "by_classification": by_classification,
            "items": [asdict(endpoint) for endpoint in endpoints],
        },
    }
