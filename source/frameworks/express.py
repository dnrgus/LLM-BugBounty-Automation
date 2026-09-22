from __future__ import annotations

# P3.2-2 (roadmap v3.2.0 Source Intelligence): the same object/method
# allowlist source/routes.py's original regex extractor used
# (`(?:app|router)\.(get|post|put|delete|patch)\(`) -- kept narrow on
# purpose. A looser match (any `.get(`/`.post(` call) would false-positive
# on unrelated calls like Map.get() or a generic HTTP client's .post().
EXPRESS_OBJECT_NAMES = {"app", "router"}
EXPRESS_METHODS = {"get", "post", "put", "delete", "patch"}


def is_express_route_call(object_name: str, method_name: str) -> bool:
    return object_name in EXPRESS_OBJECT_NAMES and method_name in EXPRESS_METHODS
