"""The proxy must accept JWT chains and map their errors like Biscuit ones."""
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

import httpx
import pytest

from aip_core.crypto import KeyPair
from aip_mcp.config import ProxyConfig
from aip_mcp.proxy import AipProxy
from aip_token.jwt_chain import JwtChain

ISSUER = "aip:web:honest.example"


class EchoHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        payload = json.dumps({"forwarded": True, "body": body.decode()}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def upstream():
    server = HTTPServer(("127.0.0.1", 0), EchoHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture(scope="module")
def issuer_key():
    return KeyPair.generate()


@pytest.fixture()
def proxy(upstream, issuer_key):
    config = ProxyConfig(
        upstream=upstream, port=0, host="127.0.0.1",
        trust_keys={ISSUER: issuer_key.public_key_multibase()},
    )
    server = AipProxy(config)
    server.start()
    yield server
    server.stop()


def jwt_token(issuer_key, issuer=ISSUER):
    return JwtChain.create_root(
        issuer=issuer, delegate="aip:key:worker", tools=["tool:search"],
        max_depth=2, ttl_seconds=3600, issuer_keypair=issuer_key,
        holder_public_key=KeyPair.generate().public_key_bytes(), budget_cents=100,
    ).serialize()


def call(proxy, token, name):
    return httpx.post(
        f"http://127.0.0.1:{proxy.port}/mcp",
        headers={"X-AIP-Token": token},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": name, "arguments": {}}},
        timeout=10.0,
    )


def test_jwt_chain_in_scope_is_forwarded(proxy, issuer_key):
    resp = call(proxy, jwt_token(issuer_key), "search")
    assert resp.status_code == 200
    assert resp.json()["forwarded"] is True


def test_jwt_chain_out_of_scope_is_403(proxy, issuer_key):
    resp = call(proxy, jwt_token(issuer_key), "delete_everything")
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "aip_scope_insufficient"


def test_jwt_chain_wrong_anchor_is_401(proxy):
    resp = call(proxy, jwt_token(KeyPair.generate()), "search")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "aip_signature_invalid"


def test_jwt_chain_root_binding_is_enforced(proxy, issuer_key):
    resp = call(proxy, jwt_token(issuer_key, issuer="aip:web:other.example"), "search")
    assert resp.status_code == 401
