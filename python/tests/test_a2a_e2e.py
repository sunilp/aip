"""End-to-end: orchestrator mints token, researcher delegates to writer, writer verifies."""
import pytest

biscuit_auth = pytest.importorskip("biscuit_auth", reason="biscuit-python not installed")

from aip_core.crypto import KeyPair
from aip_token.chained import ChainedToken

from aip_a2a import (
    A2AVerifyMiddleware,
    append_delegation_block,
    verify_a2a_task,
)


def test_full_chain_orchestrator_researcher_writer():
    orchestrator = "aip:web:acme.com/orchestrator"
    researcher = "aip:web:acme.com/researcher"
    writer = "aip:web:acme.com/writer"

    # Orchestrator mints root authority and delegates to researcher.
    root_kp = KeyPair.generate()
    authority = ChainedToken.create_authority(
        issuer=orchestrator,
        scopes=["research:read", "research:write", "write:draft"],
        budget_cents=500,
        max_depth=3,
        ttl_seconds=3600,
        keypair=root_kp,
    )
    to_researcher = append_delegation_block(
        authority,
        delegator=orchestrator,
        delegate=researcher,
        scopes=["research:read", "write:draft"],
        context="research-task-1",
        budget_cents=200,
    )

    # Researcher receives task — middleware verifies.
    received = {"params": {"metadata": {"aip_token": to_researcher.to_base64()}}}
    researcher_calls = []

    def researcher_handler(body, *, context):
        researcher_calls.append(context.subject)
        # Researcher then delegates to writer.
        to_writer = append_delegation_block(
            to_researcher,
            delegator=researcher,
            delegate=writer,
            scopes=["write:draft"],
            context="draft-1",
            budget_cents=50,
        )
        # Writer middleware verifies.
        writer_calls = []

        def writer_handler(body2, *, context):
            writer_calls.append((context.subject, context.chain_depth))
            return {"result": "draft delivered"}

        writer_mw = A2AVerifyMiddleware(
            writer_handler,
            own_aip_id=writer,
            root_public_key_bytes=root_kp.public_key_bytes(),
            required_scope="write:draft",
        )
        writer_response = writer_mw({"params": {"metadata": {"aip_token": to_writer.to_base64()}}})
        assert writer_response == {"result": "draft delivered"}
        assert writer_calls == [(writer, 2)]
        return {"result": "ok"}

    researcher_mw = A2AVerifyMiddleware(
        researcher_handler,
        own_aip_id=researcher,
        root_public_key_bytes=root_kp.public_key_bytes(),
        required_scope="research:read",
    )
    response = researcher_mw(received)
    assert response == {"result": "ok"}
    assert researcher_calls == [researcher]


def test_writer_rejects_overreaching_scope():
    """Writer's middleware requires 'write:draft' but the chain only delegates 'research:read'."""
    orchestrator = "aip:web:acme.com/orchestrator"
    researcher = "aip:web:acme.com/researcher"
    writer = "aip:web:acme.com/writer"

    root_kp = KeyPair.generate()
    authority = ChainedToken.create_authority(
        issuer=orchestrator,
        scopes=["research:read"],  # only research:read in the root
        budget_cents=500, max_depth=3, ttl_seconds=3600, keypair=root_kp,
    )
    to_researcher = append_delegation_block(
        authority, delegator=orchestrator, delegate=researcher,
        scopes=["research:read"], context="r1",
    )
    to_writer = append_delegation_block(
        to_researcher, delegator=researcher, delegate=writer,
        scopes=["research:read"], context="w1",
    )

    def writer_handler(body, *, context):
        pytest.fail("handler should not be called")

    writer_mw = A2AVerifyMiddleware(
        writer_handler,
        own_aip_id=writer,
        root_public_key_bytes=root_kp.public_key_bytes(),
        required_scope="write:draft",  # not in chain
    )
    response = writer_mw({"params": {"metadata": {"aip_token": to_writer.to_base64()}}})
    assert response["error"]["code"] == "aip_scope_insufficient"
    assert response["status"] == 403
