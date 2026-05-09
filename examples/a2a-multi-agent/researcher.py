"""A2A researcher server. Verifies incoming token, delegates to writer, forwards work."""

import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from aip_a2a import A2AVerifyMiddleware, append_delegation_block
from aip_token.chained import ChainedToken

RESEARCHER_ID = "aip:web:example.local/researcher"
WRITER_ID = "aip:web:example.local/writer"
WRITER_URL = "http://localhost:8002"
PORT = 8001


def forward_to_writer(token_str: str, root_pk: bytes) -> dict:
    # Restore the chain so we can append.
    token = ChainedToken.from_base64(token_str, root_pk)
    extended = append_delegation_block(
        token,
        delegator=RESEARCHER_ID,
        delegate=WRITER_ID,
        scopes=["write:draft"],
        context="draft-summary",
        budget_cents=50,
    )
    body = {
        "jsonrpc": "2.0",
        "method": "tasks/send",
        "params": {
            "task_id": "writer-1",
            "message": {"role": "user", "parts": [{"text": "Draft 3 paragraphs on AIP."}]},
            "metadata": {"aip_token": extended.to_base64()},
        },
    }
    req = urllib.request.Request(
        WRITER_URL, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


def make_handler() -> A2AVerifyMiddleware:
    pubkey_hex = os.environ["ROOT_PUBKEY"]
    root_pk = bytes.fromhex(pubkey_hex)

    def handler(body, *, context):
        print(f"researcher: verified subject={context.subject} depth={context.chain_depth}", flush=True)
        token_str = body["params"]["metadata"]["aip_token"]
        writer_response = forward_to_writer(token_str, root_pk)
        return {"jsonrpc": "2.0", "id": body.get("params", {}).get("task_id"), "result": writer_response.get("result")}

    return A2AVerifyMiddleware(
        handler,
        own_aip_id=RESEARCHER_ID,
        root_public_key_bytes=root_pk,
        required_scope="research:read",
    )


class Handler(BaseHTTPRequestHandler):
    middleware: A2AVerifyMiddleware

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(length).decode() or "{}")
        response = self.middleware(body)
        status = response.get("status", 200) if "error" in response else 200
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())


def main():
    Handler.middleware = make_handler()
    print(f"researcher listening on :{PORT} as {RESEARCHER_ID}", flush=True)
    HTTPServer(("", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
