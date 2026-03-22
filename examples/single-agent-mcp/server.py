#!/usr/bin/env python3
"""MCP tool server that requires AIP compact-token authentication.

Endpoints:
  GET  /.well-known/aip/tools/search.json   -- server identity document
  POST /tools/search                         -- authenticated tool endpoint

Start with:
  python examples/single-agent-mcp/server.py

Optionally set AGENT_PUBLIC_KEY_HEX to the agent's 32-byte Ed25519 public
key in hex.  If not set, the server generates a keypair and prints both
halves so you can use the private key with the client.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

# ---------------------------------------------------------------------------
# Make the AIP SDK importable when running from the repo root.
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "python"))

from aip_core import KeyPair, AipId
from aip_core.document import IdentityDocument, PublicKeyEntry
from aip_token import CompactToken, AipClaims, TokenError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PORT = 8340
REQUIRED_SCOPE = "tool:search"


def _load_agent_public_key() -> bytes:
    """Return the 32-byte Ed25519 public key of the known agent.

    If AGENT_PUBLIC_KEY_HEX is set, decode it.  Otherwise, generate a fresh
    keypair and print both halves for easy copy-paste into the client.
    """
    hex_key = os.environ.get("AGENT_PUBLIC_KEY_HEX")
    if hex_key:
        return bytes.fromhex(hex_key)

    print("[server] No AGENT_PUBLIC_KEY_HEX set -- generating a demo agent keypair.")
    demo_kp = KeyPair.generate()
    pub_bytes = demo_kp.public_key_bytes()
    priv_bytes = demo_kp._private_key.private_bytes_raw()
    print(f"[server] Demo agent public  key (hex): {pub_bytes.hex()}")
    print(f"[server] Demo agent private key (hex): {priv_bytes.hex()}")
    print("[server] Pass the private key to the client:")
    print(f"  AGENT_PRIVATE_KEY_HEX={priv_bytes.hex()} python examples/single-agent-mcp/client.py")
    print()
    return pub_bytes


# ---------------------------------------------------------------------------
# Build the server's own identity document
# ---------------------------------------------------------------------------
def _build_identity_document(server_kp: KeyPair) -> str:
    """Return the JSON identity document for this server."""
    doc = {
        "aip": "1.0",
        "id": f"aip:web:localhost:{PORT}/tools/search",
        "name": "MCP Search Tool Server",
        "public_keys": [
            {
                "id": f"aip:web:localhost:{PORT}/tools/search#key-0",
                "type": "Ed25519",
                "public_key_multibase": server_kp.public_key_multibase(),
            }
        ],
        "protocols": [
            {
                "type": "mcp",
                "endpoint": f"http://localhost:{PORT}/tools/search",
                "scopes": [REQUIRED_SCOPE],
            }
        ],
    }
    return json.dumps(doc, indent=2)


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class AipHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler for the demo MCP server."""

    server_kp: KeyPair  # set after class definition
    agent_pubkey: bytes  # set after class definition
    identity_json: str   # set after class definition

    # Silence per-request log lines from BaseHTTPRequestHandler
    def log_message(self, fmt, *args):  # noqa: D401
        print(f"[server] {fmt % args}")

    # -- GET ----------------------------------------------------------------
    def do_GET(self):
        if self.path == "/.well-known/aip/tools/search.json":
            self._send_json(200, self.identity_json)
        else:
            self._send_json(404, json.dumps({"error": "not found"}))

    # -- POST ---------------------------------------------------------------
    def do_POST(self):
        # Consume the request body so the connection stays clean.
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            self.rfile.read(content_length)

        if self.path != "/tools/search":
            self._send_json(404, json.dumps({"error": "not found"}))
            return

        # 1. Extract the AIP token header
        token_str = self.headers.get("X-AIP-Token")
        if not token_str:
            print("[server] Rejecting request: no X-AIP-Token header")
            self._send_json(401, json.dumps({
                "error": {
                    "code": "aip_token_missing",
                    "message": "No AIP token provided",
                }
            }))
            return

        # 2. Verify the token signature and expiry
        try:
            token = CompactToken.verify(token_str, self.agent_pubkey)
        except TokenError as exc:
            code = exc.error_code()
            print(f"[server] Token verification failed: {code} -- {exc}")
            status = 401 if code in ("signature_invalid", "token_expired", "token_malformed") else 403
            self._send_json(status, json.dumps({
                "error": {
                    "code": f"aip_{code}",
                    "message": str(exc),
                }
            }))
            return

        # 3. Check scope
        if not token.has_scope(REQUIRED_SCOPE):
            print(f"[server] Scope check failed: token has {token.claims.scope}, need {REQUIRED_SCOPE!r}")
            self._send_json(403, json.dumps({
                "error": {
                    "code": "aip_scope_insufficient",
                    "message": f"Token scope {token.claims.scope} does not include '{REQUIRED_SCOPE}'",
                }
            }))
            return

        # 4. Success
        print(f"[server] Authenticated request from {token.claims.iss}")
        self._send_json(200, json.dumps({
            "results": [
                {
                    "title": "AIP Protocol",
                    "url": "https://github.com/sunilp/aip",
                }
            ]
        }))

    # -- helpers ------------------------------------------------------------
    def _send_json(self, status: int, body: str):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    # Server identity
    server_kp = KeyPair.generate()

    # Known agent
    agent_pubkey = _load_agent_public_key()

    # Build identity doc
    identity_json = _build_identity_document(server_kp)

    # Attach to handler class
    AipHandler.server_kp = server_kp
    AipHandler.agent_pubkey = agent_pubkey
    AipHandler.identity_json = identity_json

    httpd = HTTPServer(("127.0.0.1", PORT), AipHandler)
    print(f"[server] Listening on http://127.0.0.1:{PORT}")
    print(f"[server] Server public key (hex): {server_kp.public_key_bytes().hex()}")
    print(f"[server] Known agent public key (hex): {agent_pubkey.hex()}")
    print(f"[server] Identity document at: http://127.0.0.1:{PORT}/.well-known/aip/tools/search.json")
    print(f"[server] Tool endpoint at:     POST http://127.0.0.1:{PORT}/tools/search")
    print()
    print("[server] Waiting for requests... (Ctrl+C to stop)")
    print()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[server] Shutting down.")
        httpd.server_close()


if __name__ == "__main__":
    main()
