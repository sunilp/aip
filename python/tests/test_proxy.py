# python/tests/test_proxy.py
import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

import httpx
import pytest

from aip_core.crypto import KeyPair
from aip_token.claims import AipClaims
from aip_token.compact import CompactToken
from aip_mcp.proxy import AipProxy
from aip_mcp.config import ProxyConfig


class EchoHandler(BaseHTTPRequestHandler):
    """Simple upstream MCP server that echoes request info."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        response = json.dumps({
            "path": self.path,
            "method": "POST",
            "body": body.decode(),
            "headers": {k: v for k, v in self.headers.items()},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format, *args):
        pass  # suppress logs in tests


@pytest.fixture(scope="module")
def upstream_server():
    """Start a mock upstream MCP server."""
    server = HTTPServer(("127.0.0.1", 0), EchoHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture(scope="module")
def keypair():
    return KeyPair.generate()


@pytest.fixture()
def proxy_server(upstream_server, keypair):
    """Start an AIP proxy pointing at the upstream server."""
    config = ProxyConfig(
        upstream=upstream_server,
        port=0,  # auto-assign
        host="127.0.0.1",
        trust_keys=[keypair.public_key_multibase()],
    )
    proxy = AipProxy(config)
    proxy.start()
    yield proxy
    proxy.stop()


def _make_token(kp, scope=None, ttl=3600, budget=1.0):
    claims = AipClaims(
        iss="aip:key:ed25519:" + kp.public_key_multibase(),
        sub="aip:web:example.com/tools/search",
        scope=scope or ["tool:search"],
        budget_usd=budget,
        max_depth=0,
        iat=int(time.time()),
        exp=int(time.time()) + ttl,
    )
    return CompactToken.create(claims, kp)


class TestProxyAuth:
    def test_valid_token_passes_through(self, proxy_server, keypair):
        token = _make_token(keypair)
        url = f"http://127.0.0.1:{proxy_server.port}/mcp/tools/search"
        resp = httpx.post(url, headers={"X-AIP-Token": token}, json={"q": "test"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["path"] == "/mcp/tools/search"

    def test_missing_token_returns_401(self, proxy_server):
        url = f"http://127.0.0.1:{proxy_server.port}/mcp/tools/search"
        resp = httpx.post(url, json={"q": "test"})
        assert resp.status_code == 401
        data = resp.json()
        assert data["error"]["code"] == "aip_token_missing"

    def test_invalid_token_returns_401(self, proxy_server):
        url = f"http://127.0.0.1:{proxy_server.port}/mcp/tools/search"
        resp = httpx.post(url, headers={"X-AIP-Token": "garbage"}, json={"q": "test"})
        assert resp.status_code == 401

    def test_wrong_key_returns_401(self, proxy_server):
        other_kp = KeyPair.generate()
        token = _make_token(other_kp)
        url = f"http://127.0.0.1:{proxy_server.port}/mcp/tools/search"
        resp = httpx.post(url, headers={"X-AIP-Token": token}, json={"q": "test"})
        assert resp.status_code == 401
        data = resp.json()
        assert data["error"]["code"] == "aip_signature_invalid"

    def test_expired_token_returns_401(self, proxy_server, keypair):
        token = _make_token(keypair, ttl=-10)
        url = f"http://127.0.0.1:{proxy_server.port}/mcp/tools/search"
        resp = httpx.post(url, headers={"X-AIP-Token": token}, json={"q": "test"})
        assert resp.status_code == 401

    def test_audit_log_in_response_headers(self, proxy_server, keypair):
        token = _make_token(keypair)
        url = f"http://127.0.0.1:{proxy_server.port}/mcp/tools/search"
        resp = httpx.post(url, headers={"X-AIP-Token": token}, json={"q": "test"})
        assert resp.status_code == 200
        assert "X-AIP-Audit" in resp.headers
        audit = json.loads(resp.headers["X-AIP-Audit"])
        assert audit["passed"] is True
