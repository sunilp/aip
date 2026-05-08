# A2A Multi-Agent Delegation Example

End-to-end demo of AIP over A2A: an **orchestrator** delegates research to a
**researcher**, and the researcher delegates writing to a **writer**. The token
chain grows from 1 → 2 → 3 blocks. Each hop attenuates scope.

```
Orchestrator
    |-- mint authority: scopes=[research:read, write:draft], max_depth=3
    |-- append delegation: delegate=researcher, scopes=[research:read, write:draft]
    v
Researcher (port 8001)
    |-- A2AVerifyMiddleware verifies chain (depth=1, scope=research:read)
    |-- append delegation: delegate=writer, scopes=[write:draft]
    v
Writer (port 8002)
    |-- A2AVerifyMiddleware verifies chain (depth=2, scope=write:draft)
    |-- handler returns drafted summary
```

## Prerequisites

```bash
cd python/
pip install -e .
```

## Run

In one terminal, start the writer:

```bash
python writer.py
```

In another terminal, start the researcher (give it the orchestrator's pubkey):

```bash
ROOT_PUBKEY=<hex from orchestrator's first run> python researcher.py
```

In a third terminal, run the orchestrator:

```bash
python orchestrator.py
```

The orchestrator prints its public key on first run; copy that into the
`ROOT_PUBKEY` env var for the researcher and writer (the researcher passes
it through to the writer via env).

## What to look for

1. Orchestrator mints the chain and POSTs to researcher.
2. Researcher logs `verified subject=aip:web:example.local/researcher depth=1`.
3. Researcher delegates and POSTs to writer.
4. Writer logs `verified subject=aip:web:example.local/writer depth=2`.
5. Writer returns the drafted summary back through the chain.

## Try to break it

- Edit `orchestrator.py` to grant `delete` scope to researcher → researcher accepts (it's in scope from the root) but writer does not have it, so any handler that requires `delete` rejects.
- Stop the writer and re-run the orchestrator → researcher gets a connection error, returns the error up the chain.
- Tamper with `delegated.to_base64()` (flip a byte) → researcher's middleware rejects with `aip_chain_invalid`.
