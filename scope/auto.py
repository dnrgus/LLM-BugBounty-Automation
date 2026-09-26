"""WP-04: safe auto-scope generation.

`bugbounty scan <url>` should not require the user to hand-write a scope
YAML for every target. But auto-generating scope is exactly where usability
can quietly erode safety (§32), so this is deliberately narrow: scope is
auto-generated ONLY for loopback and private-network hosts (a local lab like
Juice Shop on 127.0.0.1). Any public/routable host still requires an explicit
--scope file, so the tool never invents authorization to hit a real target.

The generated scope mirrors the conservative defaults of
config/scope.example.yaml: read-only automated scanning, state-changing
requests recorded but not sent (dry_run), destructive actions and DoS off,
delete/payment/etc. blocked.
"""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlparse


class ScopeNotAutoAllowedError(ValueError):
    """Raised when a target is not eligible for auto-scope (a public host);
    the caller must supply an explicit --scope file instead."""


def _host_and_port(target: str) -> tuple[str, int | None]:
    parsed = urlparse(target if "://" in target else f"//{target}")
    return (parsed.hostname or ""), parsed.port


def is_auto_allowed_host(host: str) -> bool:
    """True only for loopback / private / link-local hosts, i.e. a local lab
    the operator is presumed to own."""
    if not host:
        return False
    if host.lower() in {"localhost", "localhost.localdomain"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # A named host that isn't localhost -- do not auto-allow.
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def build_auto_scope(target: str) -> dict[str, Any]:
    """Build a conservative in-memory scope config for a loopback/private
    target. Raises ScopeNotAutoAllowedError for anything else."""
    host, port = _host_and_port(target)
    if not is_auto_allowed_host(host):
        raise ScopeNotAutoAllowedError(
            f"auto-scope only covers localhost/private targets; '{host or target}' needs an "
            f"explicit --scope file confirming you are authorized to test it"
        )
    scheme = urlparse(target).scheme or "http"
    authority = host if port is None else f"{host}:{port}"
    base = f"{scheme}://{authority}"
    return {
        "program": f"auto-local-{host}",
        "scope": {
            "domains": [host],
            "allow_subdomains": False,
            "deny_domains": [],
            # Both the bare authority and everything under it: the scope
            # matcher treats "<base>/*" as requiring a path, so the base URL
            # itself needs its own pattern.
            "url_patterns": [base, f"{base}/*"],
            "deny_url_patterns": [],
        },
        "testing": {
            "automated_scanning": True,
            "prompt_injection": True,
            "system_prompt_leak": True,
            "indirect_injection": True,
            "rag_security": True,
            "tool_abuse": False,
            "agent_security": False,
            "destructive_actions": False,
            "denial_of_service": False,
            "cross_user_data_access": False,
            "state_changing_requests": "dry_run",
        },
        "limits": {
            "requests_per_second": 5,
            "concurrency": 3,
            "max_requests_per_run": 3000,
        },
        "approval_required": ["external_callback", "file_write"],
        "blocked_actions": ["send_message", "account_state_change", "payment", "delete"],
    }
