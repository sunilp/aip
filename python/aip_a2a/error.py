"""Error types for AIP A2A binding. Codes match aip-bindings-mcp.md §4.2 conventions."""

from __future__ import annotations


class A2AError(Exception):
    code: str = "aip_a2a_error"

    def __init__(self, message: str = "") -> None:
        super().__init__(message)


class AudienceError(A2AError):
    code = "aip_audience_mismatch"


class ScopeError(A2AError):
    code = "aip_scope_insufficient"

    def __init__(self, scope: str) -> None:
        super().__init__(f"Token does not authorize scope {scope!r}")


class ChainError(A2AError):
    code = "aip_chain_invalid"


class ExpiryError(A2AError):
    code = "aip_token_expired"

    def __init__(self) -> None:
        super().__init__("Token has expired")


class DepthError(A2AError):
    code = "aip_depth_exceeded"

    def __init__(self, max_depth: int) -> None:
        super().__init__(f"Chain depth exceeds max_depth={max_depth}")


def a2a_error_response(code: str, message: str, status: int) -> dict:
    return {
        "error": {"code": code, "message": message},
        "status": status,
    }
