"""P4.5 WP-01 (v5.0 plan 5.1): endpoint inventory with state-changing
methods and inferred/captured request body shape."""

import json
from pathlib import Path

import pytest

from source.audit import collect_source_items
from source.endpoints import (
    CapturedRequest,
    EndpointSpec,
    apply_captured_request,
    build_endpoint_inventory,
    expand_methods,
    extract_path_params,
    load_captured_requests,
    path_template_regex,
)


def _inventory(fixture: str) -> dict[tuple[str, str], EndpointSpec]:
    _, items = collect_source_items(Path("tests/fixtures/source") / fixture)
    return {(spec.method, spec.path): spec for spec in build_endpoint_inventory(items)}


def test_expand_methods_handles_route_labels() -> None:
    assert expand_methods("ROUTE") == ["GET"]
    assert expand_methods("ANY") == ["GET"]
    assert expand_methods("GET|PATCH") == ["GET", "PATCH"]
    assert expand_methods("delete") == ["DELETE"]


def test_extract_path_params_supports_every_framework_syntax() -> None:
    assert extract_path_params("/api/notes/<int:note_id>") == ["note_id"]
    assert extract_path_params("/orders/{order_id}") == ["order_id"]
    assert extract_path_params("/api/invoices/:invoiceId") == ["invoiceId"]
    assert extract_path_params("/api/users/[id]") == ["id"]


def test_path_template_regex_matches_concrete_paths() -> None:
    assert path_template_regex("/api/notes/<int:note_id>").match("/api/notes/42")
    assert path_template_regex("/api/invoices/:invoiceId").match("/api/invoices/inv_1/")
    assert not path_template_regex("/api/notes/<int:note_id>").match("/api/notes/42/extra")


def test_flask_inventory_includes_state_changing_methods_with_body_shape() -> None:
    inventory = _inventory("rest_api_app")
    create = inventory[("POST", "/api/notes")]
    assert create.risk == "state_changing"
    assert create.body_format == "json"
    assert create.body_fields == ["title", "body"]  # includes the aliased `payload["title"]`
    assert create.schema_source == "inferred"

    assert inventory[("PUT", "/api/notes/<int:note_id>")].body_fields == ["title"]
    delete = inventory[("DELETE", "/api/notes/<int:note_id>")]
    assert delete.risk == "destructive"
    assert delete.path_params == ["note_id"]

    assert inventory[("PATCH", "/api/profile")].body_format == "form"
    assert inventory[("GET", "/api/profile")].body_format == "none"  # same handler, read-only method
    assert inventory[("POST", "/api/avatar")].body_format == "multipart"
    assert inventory[("GET", "/api/search")].query_params == ["q"]


def test_fastapi_inventory_reads_pydantic_body_and_scalar_query_params() -> None:
    inventory = _inventory("fastapi_app")
    create = inventory[("POST", "/orders")]
    assert create.body_format == "json"
    assert create.body_fields == ["item_id", "quantity"]
    assert inventory[("GET", "/items")].query_params == ["limit", "category"]
    # path params and Depends(...) are not query params
    assert inventory[("GET", "/orders/{order_id}")].query_params == []


def test_express_inventory_reads_destructured_and_member_body_fields() -> None:
    pytest.importorskip("tree_sitter")
    inventory = _inventory("express_crud")
    assert inventory[("POST", "/api/invoices")].body_fields == ["amount", "currency"]
    assert inventory[("PATCH", "/api/invoices/:invoiceId")].body_fields == ["note"]
    assert inventory[("DELETE", "/api/invoices/:invoiceId")].risk == "destructive"
    assert inventory[("POST", "/api/receipts")].body_format == "multipart"
    assert inventory[("GET", "/api/search")].query_params == ["q"]


def test_endpoint_spec_id_is_deterministic_and_round_trips() -> None:
    first = _inventory("rest_api_app")[("POST", "/api/notes")]
    second = _inventory("rest_api_app")[("POST", "/api/notes")]
    assert first.id == second.id
    restored = EndpointSpec.from_dict(first.to_dict())
    assert restored.id == first.id
    assert restored.body_fields == first.body_fields


def test_captured_request_overrides_inference() -> None:
    spec = _inventory("rest_api_app")[("PUT", "/api/notes/<int:note_id>")]
    captured = [
        CapturedRequest(method="PUT", path="/api/notes/7", content_type="application/json", body={"title": "t", "pinned": True})
    ]
    updated = apply_captured_request(spec, captured)
    assert updated.schema_source == "captured"
    assert updated.body_fields == ["pinned", "title"]
    assert updated.example_body == {"title": "t", "pinned": True}


def test_captured_request_for_another_method_is_ignored() -> None:
    spec = _inventory("rest_api_app")[("PUT", "/api/notes/<int:note_id>")]
    assert apply_captured_request(spec, [CapturedRequest(method="GET", path="/api/notes/7")]) == spec


def test_load_captured_requests_reads_har_without_header_values(tmp_path: Path) -> None:
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://ai.example.com/api/notes?draft=1",
                        "headers": [{"name": "Authorization", "value": "Bearer secret-token"}],
                        "postData": {"mimeType": "application/json", "text": json.dumps({"title": "x"})},
                    }
                }
            ]
        }
    }
    path = tmp_path / "capture.har"
    path.write_text(json.dumps(har), encoding="utf-8")
    (request,) = load_captured_requests(path)
    assert request.method == "POST"
    assert request.path == "/api/notes"
    assert request.query_params == ["draft"]
    assert request.body == {"title": "x"}
    assert request.header_names == ["authorization"]
    assert "secret-token" not in repr(request)


def test_load_captured_requests_reads_plain_json_form_body(tmp_path: Path) -> None:
    path = tmp_path / "requests.json"
    path.write_text(
        json.dumps([{"method": "patch", "path": "/api/profile", "content_type": "application/x-www-form-urlencoded", "body": "display_name=a"}]),
        encoding="utf-8",
    )
    (request,) = load_captured_requests(path)
    assert request.method == "PATCH"
    assert request.body == {"display_name": "a"}
