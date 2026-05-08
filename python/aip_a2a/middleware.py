"""Middleware for wrapping A2A task handlers with AIP verification.

Framework-agnostic: the middleware is a callable that accepts a parsed task body
and returns either the handler's response or an A2A error response. Adapters for
specific A2A frameworks (asyncio, http.server, FastAPI) layer on top of this.
"""

from __future__ import annotations

from typing import Callable

from aip_a2a.error import A2AError, AudienceError, ScopeError, a2a_error_response
from aip_a2a.verify import verify_a2a_task


# Status codes per spec §5 / aip-bindings-mcp.md §4.2.
_STATUS_BY_CODE = {
    "aip_chain_invalid": 401,
    "aip_token_expired": 401,
    "aip_scope_insufficient": 403,
    "aip_audience_mismatch": 403,
    "aip_depth_exceeded": 403,
}


class A2AVerifyMiddleware:
    """Verify AIP tokens on incoming A2A task bodies; pass to handler on success.

    Usage:
        def handler(body, *, context):
            # context.subject, context.chain_depth, context.issuer
            return {"jsonrpc": "2.0", "result": "..."}

        mw = A2AVerifyMiddleware(
            handler,
            own_aip_id="aip:web:acme.com/researcher",
            root_public_key_bytes=root_kp.public_key_bytes(),
            required_scope="research:read",
        )
        response = mw(parsed_request_body)
    """

    def __init__(
        self,
        handler: Callable,
        *,
        own_aip_id: str,
        root_public_key_bytes: bytes,
        required_scope: str,
    ) -> None:
        self._handler = handler
        self._own_aip_id = own_aip_id
        self._root_public_key_bytes = root_public_key_bytes
        self._required_scope = required_scope

    def __call__(self, body: dict) -> dict:
        try:
            verified = verify_a2a_task(
                body,
                expected_audience=self._own_aip_id,
                root_public_key_bytes=self._root_public_key_bytes,
                required_scope=self._required_scope,
            )
        except A2AError as exc:
            status = _STATUS_BY_CODE.get(exc.code, 400)
            return a2a_error_response(exc.code, str(exc), status)
        return self._handler(body, context=verified)
