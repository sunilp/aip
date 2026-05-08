"""A2A multi-agent example — orchestrator.

Mints an authority token with broad scope, delegates a narrowed subset to the
researcher, and sends an A2A task with the token in metadata.aip_token.
"""

import json
import urllib.request
from pathlib import Path

from aip_a2a import append_delegation_block
from aip_core.crypto import KeyPair
from aip_token.chained import ChainedToken

KEYS_DIR = Path(__file__).parent / "keys"
RESEARCHER_URL = "http://localhost:8001/tasks/send"

ORCHESTRATOR_ID = "aip:web:example.local/orchestrator"
RESEARCHER_ID = "aip:web:example.local/researcher"


def load_or_create_root_keypair() -> KeyPair:
    KEYS_DIR.mkdir(exist_ok=True)
    sk_path = KEYS_DIR / "orchestrator.sk"
    if sk_path.exists():
        return KeyPair.from_seed(sk_path.read_bytes())
    kp = KeyPair.generate()
    sk_path.write_bytes(kp.seed_bytes())
    (KEYS_DIR / "orchestrator.pub").write_bytes(kp.public_key_bytes())
    return kp


def main() -> None:
    root_kp = load_or_create_root_keypair()

    authority = ChainedToken.create_authority(
        issuer=ORCHESTRATOR_ID,
        scopes=["research:read", "write:draft"],
        budget_cents=500,
        max_depth=3,
        ttl_seconds=3600,
        keypair=root_kp,
    )
    delegated = append_delegation_block(
        authority,
        delegator=ORCHESTRATOR_ID,
        delegate=RESEARCHER_ID,
        scopes=["research:read", "write:draft"],
        context="produce-summary-of-aip",
        budget_cents=200,
    )

    body = {
        "jsonrpc": "2.0",
        "method": "tasks/send",
        "params": {
            "task_id": "task-001",
            "message": {"role": "user", "parts": [{"text": "Summarize AIP in 3 paragraphs."}]},
            "metadata": {"aip_token": delegated.to_base64()},
        },
    }
    req = urllib.request.Request(
        RESEARCHER_URL,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        print("status:", resp.status)
        print("body:", resp.read().decode())

    # Print public key so researcher/writer can verify; in a real deployment,
    # they would resolve this from the orchestrator's identity document.
    print("\nroot_public_key (hex):", root_kp.public_key_bytes().hex())


if __name__ == "__main__":
    main()
