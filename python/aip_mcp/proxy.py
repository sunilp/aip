"""AIP MCP Auth Proxy -- drop-in authentication for any MCP server.

Sits between an MCP client and an MCP server, verifying AIP tokens
and running security self-audit on every request.

    Warning: JWT chains are bearer-equivalent here. Any prefix of a valid
    JWT chain also verifies and carries an earlier holder's wider authority,
    and this module does not verify proof of possession. Biscuit chains are
    not affected.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

import httpx

from aip_core.crypto import KeyPair
from aip_mcp.middleware import extract_token, detect_mode
from aip_mcp.error import aip_error_response
from aip_mcp.audit import audit_compact, audit_chained, audit_jwt_chain, AuditResult
from aip_mcp.config import ProxyConfig
from aip_mcp.request import parse_mcp_request
from aip_token.error import TokenError

logger = logging.getLogger("aip-proxy")

#: Section 6.1 maps authorization failures to 403 and authentication failures
#: to 401. Getting this wrong tells a client to re-authenticate when the real
#: answer is that its credential is valid and simply does not permit the call.
_FORBIDDEN_CODES = frozenset(
    {
        "aip_scope_insufficient",
        "aip_budget_exceeded",
        "aip_depth_exceeded",
    }
)


def _aip_code(code: str) -> str:
    """Ensure error code has 'aip_' prefix for protocol conformance."""
    if code.startswith("aip_"):
        return code
    return f"aip_{code}"


def _status_for(code: str) -> int:
    return 403 if code in _FORBIDDEN_CODES else 401


class _ProxyHandler(BaseHTTPRequestHandler):
    """HTTP request handler that verifies AIP tokens and forwards to upstream."""

    def do_POST(self):
        self._handle()

    def do_GET(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def _handle(self):
        config: ProxyConfig = self.server.aip_config

        # Read request body
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""

        # Extract token
        headers_dict = {k: v for k, v in self.headers.items()}
        token_str = extract_token(headers_dict)

        if not token_str:
            self._send_error("aip_token_missing", "No X-AIP-Token header", 401)
            self._log_decision("DENY", "token_missing", None)
            return

        # Which tool, if any, this request invokes. V6 evaluates the token's
        # policy against the tool actually being called, so the proxy has to
        # read it out of the JSON-RPC body rather than forward blindly.
        mcp_request = parse_mcp_request(body)
        if mcp_request.batch and mcp_request.tool is None and mcp_request.method is None:
            self._send_error(
                "aip_scope_insufficient",
                "JSON-RPC batch invoking multiple tools cannot be authorized "
                "by a single policy evaluation; send one tool call per request",
                403,
            )
            self._log_decision("DENY", "batch_multi_tool", None)
            return

        required_scope = mcp_request.required_scope

        try:
            verified, audit_result = self._verify(token_str, required_scope)
        except TokenError as e:
            code = _aip_code(e.error_code())
            self._send_error(code, str(e), _status_for(code))
            self._log_decision("DENY", code, None)
            return
        except Exception as e:  # noqa: BLE001 - never leak an internal traceback
            logger.debug("verification raised", exc_info=True)
            self._send_error("aip_signature_invalid", str(e), 401)
            self._log_decision("DENY", "aip_signature_invalid", None)
            return

        # Audit failed (errors, not just warnings)
        if audit_result and not audit_result.passed:
            self._send_error(
                "aip_audit_failed",
                f"Security audit failed: {'; '.join(audit_result.errors)}",
                403,
            )
            self._log_decision("DENY", "audit_failed", audit_result)
            return

        # Forward to upstream
        try:
            upstream_url = config.upstream.rstrip("/") + self.path
            upstream_resp = httpx.request(
                method=self.command,
                url=upstream_url,
                headers=headers_dict,
                content=body,
                timeout=30.0,
            )
        except httpx.RequestError as e:
            self._send_error("upstream_error", f"Upstream error: {e}", 502)
            self._log_decision("ERROR", "upstream_error", audit_result)
            return

        # Send response back with audit header
        self.send_response(upstream_resp.status_code)
        for key, val in upstream_resp.headers.items():
            if key.lower() not in ("transfer-encoding", "content-encoding", "content-length"):
                self.send_header(key, val)

        # Add audit result header
        if audit_result:
            self.send_header("X-AIP-Audit", json.dumps(audit_result.to_dict()))

        resp_body = upstream_resp.content
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

        self._log_decision("ALLOW", "ok", audit_result)

    def _verify(self, token_str: str, required_scope: str | None):
        """Run the verification algorithm and return (token, audit result).

        Raises TokenError on any failure. This is the proxy's whole security
        boundary, so it deliberately does the steps the transport is supposed
        to do rather than trusting a signature check alone:

        * V1 and V3 through V6 come from the token implementation.
        * V2 (root binding) is done here, by confirming that the key which
          verified the token is the key configured for the issuer that token
          declares. Without it, a deployment trusting two issuers would accept
          a token signed by one while it claims the identity of the other.
        * V6 runs only when the request names a tool. Requests that name none
          (`initialize`, `tools/list`) still get V1 through V5.
        """
        config: ProxyConfig = self.server.aip_config
        anchors: dict[str | None, bytes] = self.server.aip_trust_anchors

        mode = detect_mode(token_str)
        last_error: TokenError | None = None

        for issuer, pub_key in anchors.items():
            try:
                if mode == "jwt-chain":
                    from aip_token.jwt_chain import JwtChain

                    token = JwtChain.verify(token_str, bytes(pub_key))
                    self._bind_root(issuer, token.issuer())
                    if required_scope is not None:
                        token.authorize(required_scope)
                    return token, audit_jwt_chain(
                        token,
                        max_depth=config.max_depth,
                        max_budget_cents=int(config.max_budget_usd * 100),
                    )

                if mode == "compact":
                    from aip_token.compact import CompactToken

                    token = CompactToken.verify(token_str, pub_key)
                    self._bind_root(issuer, token.claims.iss)
                    if required_scope is not None and not token.has_scope(
                        required_scope
                    ):
                        raise TokenError(
                            f"Token does not authorize {required_scope}",
                            "scope_insufficient",
                        )
                    return token, audit_compact(token)

                from aip_token.chained import ChainedToken

                token = ChainedToken.from_base64(token_str, pub_key)
                self._bind_root(issuer, token.issuer())

                if required_scope is None:
                    token.verify_chain(pub_key)
                else:
                    token.authorize(required_scope, pub_key)

                return token, audit_chained(
                    token,
                    max_depth=config.max_depth,
                    max_budget_cents=int(config.max_budget_usd * 100),
                )
            except TokenError as e:
                # A signature mismatch means "wrong anchor, try the next one".
                # Anything else is a real verdict about a token that already
                # verified, and must not be masked by trying another key.
                if e.error_code() in ("signature_invalid", "aip_signature_invalid"):
                    last_error = e
                    continue
                raise
            except Exception as e:  # noqa: BLE001
                last_error = TokenError(str(e), "signature_invalid")
                continue

        raise last_error or TokenError("Token verification failed", "signature_invalid")

    @staticmethod
    def _bind_root(configured_issuer: str | None, declared_issuer: str | None) -> None:
        """V2: the verifying key must belong to the issuer the token declares."""
        if configured_issuer is None:
            # Single unbound anchor. There is no second issuer to be confused
            # with, and the operator was warned at startup.
            return
        if declared_issuer != configured_issuer:
            raise TokenError(
                f"token declares issuer {declared_issuer!r} but verified under the "
                f"key configured for {configured_issuer!r}",
                "identity_unresolvable",
            )

    def _send_error(self, code: str, message: str, status: int):
        resp = aip_error_response(code, message, status)
        body = json.dumps(resp).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _log_decision(self, decision: str, reason: str, audit: AuditResult | None):
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "decision": decision,
            "reason": reason,
            "path": self.path,
            "method": self.command,
        }
        if audit:
            entry["audit"] = audit.to_dict()
        logger.info(json.dumps(entry))

    def log_message(self, format, *args):
        pass  # use our own logger


class AipProxy:
    """AIP MCP Auth Proxy server."""

    def __init__(self, config: ProxyConfig):
        self.config = config
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

        # Trust anchors, keyed by the AIP issuer the key belongs to. A None key
        # means "one unbound anchor", which cannot support step V2 but is not
        # ambiguous either.
        self.trust_anchors: dict[str | None, bytes] = self._build_anchors(config)

    @staticmethod
    def _build_anchors(config: ProxyConfig) -> dict[str | None, bytes]:
        """Decode configured trust keys, refusing configurations V2 cannot check.

        A mapping of issuer to key lets the proxy confirm that the key which
        verified a token belongs to the issuer that token declares. A bare list
        carries no such binding: with two or more keys, a token signed by one
        trusted issuer can claim the identity of another and the proxy has no
        way to notice. That configuration is refused rather than served.
        """
        raw = config.trust_keys

        def decode(key_str: str) -> bytes:
            # Strip "ed25519:" prefix if present
            mb = key_str.split(":")[-1] if ":" in key_str else key_str
            return KeyPair.decode_multibase(mb)

        if isinstance(raw, dict):
            return {issuer: decode(key) for issuer, key in raw.items()}

        keys = list(raw)
        if len(keys) > 1:
            raise ValueError(
                "trust_keys was given as a list of "
                f"{len(keys)} keys, which cannot be bound to issuers. Step V2 "
                "of the verification algorithm requires knowing which issuer "
                "each key belongs to, and without it a token signed by one "
                "trusted issuer can claim the identity of another. Configure "
                "trust_keys as a mapping instead:\n\n"
                '  [proxy.trust_keys]\n'
                '  "aip:web:example.com" = "ed25519:..."\n'
            )
        if len(keys) == 1:
            logger.warning(
                "trust_keys has a single unbound key; step V2 (root binding) is "
                "not enforced. Use a mapping of issuer to key to enable it."
            )
            return {None: decode(keys[0])}
        return {}

    @property
    def port(self) -> int:
        if self._server:
            return self._server.server_address[1]
        return self.config.port

    def start(self):
        """Start the proxy server in a background thread."""
        self._server = HTTPServer(
            (self.config.host, self.config.port), _ProxyHandler
        )
        self._server.aip_config = self.config
        self._server.aip_trust_anchors = self.trust_anchors
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info(
            f"AIP proxy listening on {self.config.host}:{self.port} "
            f"-> {self.config.upstream}"
        )

    def stop(self):
        """Stop the proxy server."""
        if self._server:
            self._server.shutdown()
            self._server = None
            self._thread = None

    def serve_forever(self):
        """Start the proxy server and block until interrupted."""
        self._server = HTTPServer(
            (self.config.host, self.config.port), _ProxyHandler
        )
        self._server.aip_config = self.config
        self._server.aip_trust_anchors = self.trust_anchors
        logger.info(
            f"AIP proxy listening on {self.config.host}:{self.port} "
            f"-> {self.config.upstream}"
        )
        try:
            self._server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down")
            self._server.shutdown()
