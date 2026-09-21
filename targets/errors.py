from __future__ import annotations


class TargetError(Exception):
    """Base class for all TargetAdapter-raised errors."""


class TargetConnectionError(TargetError):
    """DNS/TCP/TLS/proxy connection failure, or a request timeout."""


class TargetAuthenticationError(TargetError):
    """Cookie/token/API key authentication failed (401/403)."""


class TargetRateLimitError(TargetError):
    """The target rejected the request as rate limited (429)."""


class TargetParseError(TargetError):
    """The response did not match the adapter's expected schema."""


class TargetSessionExpiredError(TargetError):
    """The target reports the session needs to be refreshed."""


class UnsupportedCapabilityError(TargetError):
    """The target does not support the capability a testcase requires."""


class TargetServerError(TargetError):
    """The target responded with a 5xx server error."""
