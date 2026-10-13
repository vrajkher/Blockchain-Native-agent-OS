"""Host-managed signing service.

Private keys live only here (on the host, in a 0700 keystore directory).
Agent harnesses and sandboxes never receive key material; they receive
signed artifacts. Revoked identities are refused.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import crypto

HOST_KEY = "host-authority"
PASSPHRASE_ENV = "BLOCKSWARM_KEYSTORE_PASSPHRASE"


class SigningError(Exception):
    pass


class SigningService:
    def __init__(self, keystore: str | Path, is_revoked: Callable[[str], bool] | None = None):
        self.keystore = Path(keystore)
        self.keystore.mkdir(parents=True, exist_ok=True)
        os.chmod(self.keystore, 0o700)
        self._keys: dict[str, Ed25519PrivateKey] = {}
        self._is_revoked = is_revoked or (lambda _id: False)
        passphrase = os.environ.get(PASSPHRASE_ENV)
        self._passphrase = passphrase.encode() if passphrase else None

    # -- key management -------------------------------------------------
    def _path(self, key_id: str) -> Path:
        if not key_id.replace("-", "").isalnum():
            raise SigningError("invalid key id")
        return self.keystore / f"{key_id}.pem"

    def _store(self, key_id: str, key: Ed25519PrivateKey) -> None:
        enc = (serialization.BestAvailableEncryption(self._passphrase)
               if self._passphrase else serialization.NoEncryption())
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
        path = self._path(key_id)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)

    def _load(self, key_id: str) -> Ed25519PrivateKey:
        key = self._keys.get(key_id)
        if key is not None:
            return key
        path = self._path(key_id)
        if not path.exists():
            raise SigningError(f"unknown key: {key_id}")
        if stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise SigningError(f"insecure key file permissions: {path}")
        loaded = serialization.load_pem_private_key(path.read_bytes(), password=self._passphrase)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise SigningError("unexpected key type")
        self._keys[key_id] = loaded
        return loaded

    def ensure_host_key(self) -> str:
        if not self._path(HOST_KEY).exists():
            self._store(HOST_KEY, Ed25519PrivateKey.generate())
        return self.host_pubkey()

    def host_pubkey(self) -> str:
        return crypto.public_bytes(self._load(HOST_KEY)).hex()

    def create_agent_key(self) -> tuple[str, str]:
        key = Ed25519PrivateKey.generate()
        pub = crypto.public_bytes(key)
        agent_id = crypto.agent_id_from_pubkey(pub)
        self._store(agent_id, key)
        self._keys[agent_id] = key
        return agent_id, pub.hex()

    def pubkey(self, key_id: str) -> str:
        return crypto.public_bytes(self._load(key_id)).hex()

    # -- signing --------------------------------------------------------
    def sign_as_host(self, domain: str, payload: Any) -> str:
        return crypto.sign(self._load(HOST_KEY), domain, payload)

    def sign_as_agent(self, agent_id: str, domain: str, payload: Any) -> str:
        if agent_id == HOST_KEY:
            raise SigningError("agents cannot sign as the host authority")
        if self._is_revoked(agent_id):
            raise SigningError(f"agent revoked: {agent_id}")
        return crypto.sign(self._load(agent_id), domain, payload)

    def forget(self, key_id: str) -> None:
        """Drop a cached key from memory (used when an agent is suspended)."""
        self._keys.pop(key_id, None)
