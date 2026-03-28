from pathlib import Path

from aip_core.crypto import KeyPair
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class KeyStore:
    """Manages Ed25519 keypairs for agents. In-memory by default, optional disk persistence."""

    def __init__(self, persist_dir: str | None = None):
        self._keys: dict[str, KeyPair] = {}
        self._persist_dir = Path(persist_dir) if persist_dir else None
        if self._persist_dir:
            self._persist_dir.mkdir(parents=True, exist_ok=True)

    def get_or_create(self, name: str) -> KeyPair:
        if name in self._keys:
            return self._keys[name]

        if self._persist_dir:
            key_file = self._persist_dir / f"{name}.key"
            if key_file.exists():
                raw = key_file.read_bytes()
                private_key = Ed25519PrivateKey.from_private_bytes(raw)
                kp = KeyPair(private_key)
                self._keys[name] = kp
                return kp

        kp = KeyPair.generate()
        self._keys[name] = kp

        if self._persist_dir:
            key_file = self._persist_dir / f"{name}.key"
            key_file.write_bytes(kp.private_key_bytes())
            key_file.chmod(0o600)

        return kp

    def has(self, name: str) -> bool:
        if name in self._keys:
            return True
        if self._persist_dir:
            return (self._persist_dir / f"{name}.key").exists()
        return False
