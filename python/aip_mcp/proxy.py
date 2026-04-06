"""AIP MCP Auth Proxy -- drop-in authentication for any MCP server.

Sits between an MCP client and an MCP server, verifying AIP tokens
and running security self-audit on every request.
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
from aip_mcp.audit import audit_compact, audit_chained, AuditResult
from aip_mcp.config import ProxyConfig
from aip_token.error import TokenError

logger = logging.getLogger("aip-proxy")


def _aip_code(code: str) -> str:
    """Ensure error code has 'aip_' prefix for protocol conformance."""
    if code.startswith("aip_"):
        return code
    return f"aip_{code}"


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
        trust_keys: list[bytes] = self.server.aip_trust_key_bytes

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

        # Try each trust key until one works
        verified = None
        audit_result = None
        last_error = None

        for pub_key in trust_keys:
            try:
                mode = detect_mode(token_str)
                if mode == "compact":
                    from aip_token.compact import CompactToken
                    verified = CompactToken.verify(token_str, pub_key)
                    audit_result = audit_compact(verified)
                else:
                    from aip_token.chained import ChainedToken
                    verified = ChainedToken.from_base64(token_str, pub_key)
                    audit_result = audit_chained(verified)
                break
            except TokenError as e:
                last_error = e
                continue
            except Exception as e:
                last_error = TokenError(str(e), "token_malformed")
                continue

        if verified is None:
            code = _aip_code(last_error.error_code()) if last_error else "aip_signature_invalid"
            msg = str(last_error) if last_error else "Token verification failed"
            status = 401
            self._send_error(code, msg, status)
            self._log_decision("DENY", code, None)
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

        # Decode trust keys from multibase
        self.trust_key_bytes: list[bytes] = []
        for key_str in config.trust_keys:
            # Strip "ed25519:" prefix if present
            mb = key_str.split(":")[-1] if ":" in key_str else key_str
            self.trust_key_bytes.append(KeyPair.decode_multibase(mb))

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
        self._server.aip_trust_key_bytes = self.trust_key_bytes
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
        self._server.aip_trust_key_bytes = self.trust_key_bytes
        logger.info(
            f"AIP proxy listening on {self.config.host}:{self.port} "
            f"-> {self.config.upstream}"
        )
        try:
            self._server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down")
            self._server.shutdown()
