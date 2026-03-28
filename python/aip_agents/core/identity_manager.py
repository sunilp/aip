from dataclasses import dataclass

from aip_agents.core.config import AIPConfig
from aip_agents.core.key_store import KeyStore
from aip_core.crypto import KeyPair


@dataclass(frozen=True)
class AIPIdentity:
    """An agent's AIP identity."""
    name: str
    aip_id: str
    public_key_bytes: bytes
    keypair: KeyPair


class IdentityManager:
    """Creates and caches AIP identities for agents."""

    def __init__(self, config: AIPConfig):
        self._config = config
        persist_dir = None
        if config.persist_keys:
            import os
            persist_dir = os.path.expanduser(f"~/.aip/keys/{config.app_name}")
        self._key_store = KeyStore(persist_dir=persist_dir)
        self._identities: dict[str, AIPIdentity] = {}
        self._root = self._create_identity(config.app_name)

    def _create_identity(self, name: str) -> AIPIdentity:
        if name in self._identities:
            return self._identities[name]
        kp = self._key_store.get_or_create(name)
        aip_id = f"aip:key:ed25519:{kp.public_key_multibase()}"
        identity = AIPIdentity(
            name=name,
            aip_id=aip_id,
            public_key_bytes=kp.public_key_bytes(),
            keypair=kp,
        )
        self._identities[name] = identity
        return identity

    def root_identity(self) -> AIPIdentity:
        return self._root

    def register(self, agent_name: str) -> AIPIdentity:
        return self._create_identity(agent_name)

    def get(self, agent_name: str) -> AIPIdentity | None:
        return self._identities.get(agent_name)

    def all(self) -> list[AIPIdentity]:
        return list(self._identities.values())
