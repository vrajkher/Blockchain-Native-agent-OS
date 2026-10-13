"""Cryptographic primitives.

Only audited, established primitives are used: Ed25519 signatures from the
``cryptography`` package and SHA-256 from the standard library. Every
signature is domain-separated so a signature produced for one message type
can never be replayed as another.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PROTOCOL = b"blockswarm/v1/"


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding used for every hash and signature."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def commitment(obj: Any) -> str:
    """Hash commitment over the canonical encoding of ``obj``."""
    return "0x" + sha256_hex(canonical_json(obj))


def new_nonce() -> str:
    return secrets.token_hex(16)


def signing_message(domain: str, payload: Any) -> bytes:
    if not domain or "\x00" in domain:
        raise ValueError("invalid signature domain")
    return PROTOCOL + domain.encode("ascii") + b"\x00" + canonical_json(payload)


def agent_id_from_pubkey(pub: bytes) -> str:
    return "bsa1" + sha256_hex(b"blockswarm-agent-id-v1" + pub)[:40]


def public_bytes(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    if isinstance(key, Ed25519PrivateKey):
        key = key.public_key()
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def sign(key: Ed25519PrivateKey, domain: str, payload: Any) -> str:
    return key.sign(signing_message(domain, payload)).hex()


def verify(pub_hex: str, signature_hex: str, domain: str, payload: Any) -> bool:
    """Return True only for a valid signature; any malformed input is False."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(bytes.fromhex(signature_hex), signing_message(domain, payload))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
