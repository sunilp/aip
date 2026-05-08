"""A2A writer server. Verifies AIP token, returns drafted summary."""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from aip_a2a import A2AVerifyMiddleware

WRITER_ID = "aip:web:example.local/writer"
PORT = 8002


def make_handler() -> A2AVerifyMiddleware:
    pubkey_hex = os.environ["ROOT_PUBKEY"]

    def handler(body, *, context):
        print(f"writer: verified subject={context.subject} depth={context.chain_depth}")
        return {
            "jsonrpc": "2.0",
            "id": body.get("params", {}).get("task_id"),
            "result": {"summary": "AIP defines verifiable cryptographic identity ... [stub]"},
        }

    return A2AVerifyMiddleware(
        handler,
        own_aip_id=WRITER_ID,
        root_public_key_bytes=bytes.fromhex(pubkey_hex),
        required_scope="write:draft",
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
    print(f"writer listening on :{PORT} as {WRITER_ID}")
    HTTPServer(("", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
