"""Parse the aip_identity extension from A2A agent cards.

Spec: spec/aip-bindings-a2a.md §2.
"""

from __future__ import annotations

from dataclasses import dataclass


class AgentCardError(Exception):
    """Raised for malformed aip_identity extensions in agent cards."""


@dataclass(frozen=True)
class AipIdentity:
    id: str
    document_url: str | None


def parse_aip_identity(agent_card: dict) -> AipIdentity | None:
    """Extract and validate aip_identity from an agent card. Returns None if absent."""
    ext = agent_card.get("aip_identity")
    if ext is None:
        return None
    if not isinstance(ext, dict):
        raise AgentCardError("aip_identity must be an object")

    aip_id = ext.get("id")
    if not aip_id or not isinstance(aip_id, str):
        raise AgentCardError("aip_identity.id is required")
    if not (aip_id.startswith("aip:web:") or aip_id.startswith("aip:key:")):
        raise AgentCardError(f"aip_identity.id must start with 'aip:web:' or 'aip:key:' (got {aip_id!r})")

    doc_url = ext.get("document_url")
    if aip_id.startswith("aip:web:"):
        if not doc_url:
            raise AgentCardError("aip_identity.document_url is required for aip:web: identifiers")
        if not isinstance(doc_url, str) or not doc_url.startswith("https://"):
            raise AgentCardError("aip_identity.document_url must be an https URL")

    return AipIdentity(id=aip_id, document_url=doc_url)
