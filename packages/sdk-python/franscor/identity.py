"""Agent identity: an Ed25519 key pair and a self-certifying agent ID.

    agent_id = "fsp:" + sha256(raw_public_key)[:32]
    kid      = sha256(public_key_pem)[:16]      (InterMesh key fingerprint)

The private key is written once, with mode 0600, and is never logged,
serialized into a card, or sent over the network. Set
`FRANSCOR_KEY_PASSPHRASE` to encrypt it at rest.
"""

from __future__ import annotations

import hashlib
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import b64, unb64

NAME_RE = re.compile(r"^[a-z0-9._-]{1,64}$")
AGENT_ID_RE = re.compile(r"^fsp:[0-9a-f]{32}$")


def franscor_home() -> Path:
    return Path(os.environ.get("FRANSCOR_HOME") or Path.home() / ".franscor")


@lru_cache(maxsize=4096)
def _load_public(pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode("utf-8"))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("expected an Ed25519 public key")
    return key


@lru_cache(maxsize=4096)
def agent_id_from_pem(pem: str) -> str:
    raw = _load_public(pem).public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    return "fsp:" + hashlib.sha256(raw).hexdigest()[:32]


@lru_cache(maxsize=4096)
def kid_from_pem(pem: str) -> str:
    return hashlib.sha256(pem.encode("utf-8")).hexdigest()[:16]


def verify_digest(pem: str, digest_hex: str, signature_b64: str) -> bool:
    try:
        _load_public(pem).verify(unb64(signature_b64), digest_hex.encode("ascii"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class Identity:
    """Holds the private key in memory. `repr` never shows it."""

    __slots__ = ("_key", "public_pem", "agent_id", "kid")

    def __init__(self, private_key: Ed25519PrivateKey):
        self._key = private_key
        self.public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        self.agent_id = agent_id_from_pem(self.public_pem)
        self.kid = kid_from_pem(self.public_pem)

    def __repr__(self) -> str:
        return f"Identity(agent_id={self.agent_id!r}, kid={self.kid!r})"

    @classmethod
    def generate(cls) -> "Identity":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "Identity":
        """Deterministic identity — for test vectors only."""
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    def sign_digest(self, digest_hex: str) -> str:
        return b64(self._key.sign(digest_hex.encode("ascii")))

    @property
    def private_key(self) -> Ed25519PrivateKey:
        """For interop with InterMesh signers. Never log or serialize it."""
        return self._key

    # -- storage ---------------------------------------------------------

    @staticmethod
    def path_for(name: str, home: Optional[Path] = None) -> Path:
        if not NAME_RE.match(name):
            raise ValueError(f"invalid identity name {name!r} (allowed: a-z 0-9 . _ -)")
        return Path(home or franscor_home()) / "identities" / f"{name}.key"

    @staticmethod
    def _password() -> Optional[bytes]:
        passphrase = os.environ.get("FRANSCOR_KEY_PASSPHRASE")
        return passphrase.encode("utf-8") if passphrase else None

    def private_pem(self) -> bytes:
        """PKCS#8 PEM, encrypted when FRANSCOR_KEY_PASSPHRASE is set. Store it, never log it."""
        password = self._password()
        encryption = (serialization.BestAvailableEncryption(password) if password
                      else serialization.NoEncryption())
        return self._key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8, encryption)

    @classmethod
    def from_private_pem(cls, pem: bytes) -> "Identity":
        key = serialization.load_pem_private_key(pem, password=cls._password())
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("not an Ed25519 private key")
        return cls(key)

    def save(self, name: str, store=None, *, replace: bool = False) -> None:
        from .keystore import default_store

        if not NAME_RE.match(name):
            raise ValueError(f"invalid identity name {name!r}")
        (store or default_store(franscor_home())).save(name, self.private_pem(), replace=replace)

    @classmethod
    def load_or_create(cls, name: str, home: Optional[Path] = None, store=None) -> "Identity":
        from .keystore import default_store

        cls.path_for(name, home)  # validates the name
        store = store or default_store(Path(home) if home else franscor_home())
        existing = store.load(name)
        if existing:
            return cls.from_private_pem(existing)
        identity = cls.generate()
        store.save(name, identity.private_pem())
        return identity
