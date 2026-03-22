#!/usr/bin/env python3
"""Tool server that verifies AIP chained (Biscuit) delegation tokens.

Endpoint:
  POST /tools/search   -- requires X-AIP-Token header with a chained token

The server also reads X-AIP-Scope to know which scope to authorize against
(defaults to "search").  The root public key is read from ROOT_PUBLIC_KEY_HEX
environment variable; if not set, it is extracted from the first request's
X-AIP-Root-Public-Key header (for demo convenience).

Start with:
  python examples/multi-agent-delegation/tool_server.py
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

# ---------------------------------------------------------------------------
# Check for biscuit-python before proceeding.
# ---------------------------------------------------------------------------
try:
    import biscuit_auth  # noqa: F401
except ImportError:
    print("ERROR: biscuit-python is required for the chained-token example.")
    print("Install it with:")
    print("  pip install biscuit-python")
    sys.exit(1)

from aip_token import ChainedToken

if ChainedToken is None:
    print("ERROR: ChainedToken could not be imported.")
    print("Make sure biscuit-python is installed:")
    print("  pip install biscuit-python")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PORT = int(os.environ.get("AIP_TOOL_PORT", "8341"))

# Mutable state: the root public key may be set at startup or provided by
# the first request for demo convenience.
_root_public_key: bytes | None = None


def _get_root_public_key() -> bytes | None:
    """Return the cached root public key, if set."""
    return _root_public_key


def _set_root_public_key(raw: bytes) -> None:
    global _root_public_key
    _root_public_key = raw


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class DelegationHandler(BaseHTTPRequestHandler):
    """HTTP handler that verifies chained AIP tokens."""

    def log_message(self, fmt, *args):  # noqa: D401
        print(f"[tool-server] {fmt % args}")

    # -- POST ---------------------------------------------------------------
    def do_POST(self):
        # Consume request body.
        content_length = int(self.headers.get("Content-Length", 0))
        body = b""
        if content_length > 0:
            body = self.rfile.read(content_length)

        if self.path != "/tools/search":
            self._send_json(404, json.dumps({"error": "not found"}))
            return

        # Determine which scope the caller wants to invoke.
        requested_scope = self.headers.get("X-AIP-Scope", "search")

        print(f'[tool-server] POST /tools/search -- verifying chained token for scope "{requested_scope}" ...')

        # 1. Extract the AIP token header.
        token_b64 = self.headers.get("X-AIP-Token")
        if not token_b64:
            print("[tool-server] Rejecting: no X-AIP-Token header.")
            self._send_json(401, json.dumps({
                "error": {
                    "code": "aip_token_missing",
                    "message": "No AIP token provided.",
                }
            }))
            return

        # 2. Resolve root public key.
        root_pk = _get_root_public_key()
        if root_pk is None:
            # Accept from header for demo convenience.
            rpk_hex = self.headers.get("X-AIP-Root-Public-Key")
            if rpk_hex:
                root_pk = bytes.fromhex(rpk_hex)
                _set_root_public_key(root_pk)
                print(f"[tool-server] Root public key set from request header: {rpk_hex}")
            else:
                print("[tool-server] Rejecting: no root public key configured.")
                self._send_json(500, json.dumps({
                    "error": {
                        "code": "aip_config_error",
                        "message": "Root public key not configured. Set ROOT_PUBLIC_KEY_HEX or send X-AIP-Root-Public-Key header.",
                    }
                }))
                return

        # 3. Deserialize and verify the chained token.
        try:
            token = ChainedToken.from_base64(token_b64, root_pk)
        except Exception as exc:
            print(f"[tool-server] Token deserialization/verification failed: {exc}")
            self._send_json(401, json.dumps({
                "error": {
                    "code": "aip_token_invalid",
                    "message": f"Chained token verification failed: {exc}",
                }
            }))
            return

        # 4. Authorize the requested scope.
        try:
            token.authorize(requested_scope, root_pk)
        except Exception as exc:
            print(f"[tool-server] Authorization failed for scope '{requested_scope}': {exc}")
            self._send_json(403, json.dumps({
                "error": {
                    "code": "aip_scope_insufficient",
                    "message": f"Authorization denied for scope '{requested_scope}': {exc}",
                }
            }))
            return

        # 5. Success -- return mock results.
        print(f"[tool-server] Authorization succeeded for scope '{requested_scope}'. Returning results.")
        self._send_json(200, json.dumps({
            "results": [
                {
                    "title": "AIP Protocol Specification",
                    "url": "https://github.com/sunilp/aip",
                    "snippet": "The Agent Identity Protocol enables secure delegation chains.",
                },
                {
                    "title": "Biscuit Authorization Tokens",
                    "url": "https://www.biscuitsec.org/",
                    "snippet": "Biscuit provides decentralized authorization with attenuation.",
                },
            ],
            "scope_used": requested_scope,
            "token_depth": token.current_depth(),
            "token_issuer": token.issuer(),
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
    global _root_public_key

    # Check for pre-configured root public key.
    rpk_hex = os.environ.get("ROOT_PUBLIC_KEY_HEX")
    if rpk_hex:
        _root_public_key = bytes.fromhex(rpk_hex)
        print(f"[tool-server] Root public key loaded from env: {rpk_hex}")
    else:
        print("[tool-server] No ROOT_PUBLIC_KEY_HEX set.")
        print("[tool-server] Will accept root public key from first request's X-AIP-Root-Public-Key header.")
        print()

    httpd = HTTPServer(("127.0.0.1", PORT), DelegationHandler)
    print(f"[tool-server] Listening on http://127.0.0.1:{PORT}")
    print(f"[tool-server] Tool endpoint: POST http://127.0.0.1:{PORT}/tools/search")
    print()
    print("[tool-server] Waiting for requests... (Ctrl+C to stop)")
    print()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[tool-server] Shutting down.")
        httpd.server_close()


if __name__ == "__main__":
    main()
