"""End-to-end payload encryption and signed agent cards (FSP 0.1 §4.1, §3.1).

The hub routes envelopes but must not read task inputs, outputs or message
data. Each agent derives an X25519 key from its Ed25519 seed (no second key to
store or rotate) and publishes the public half as ``enc_key`` in its card.
The card is signed by the agent (``card_sig``), so a hub cannot swap the
encryption key without breaking a signature bound to the agent ID.

    shared = X25519(ephemeral_private, recipient_enc_key)
    key    = HKDF-SHA256(shared, salt = epk || recipient_enc_key, info = "fsp-0.1 payload", 32)
    sealed = AES-256-GCM(key, nonce, canonical(data), aad = canonical({type, from, to, ref}))

The AAD binds a ciphertext to its envelope type, sender, recipient and task
(or topic): it cannot be replayed into another task or redirected.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import errors as E
from .canonical import b64, canonical_bytes, canonical_hash, unb64
from .identity import Identity, agent_id_from_pem, verify_digest

ALG = "X25519-HKDF-SHA256-A256GCM"
INFO = b"fsp-0.1 payload"
DERIVE_INFO = b"fsp-0.1 x25519"
RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


_ENC_KEYS: Dict[str, X25519PrivateKey] = {}  # agent_id -> derived key (process-local)


def enc_private_key(identity: Identity) -> X25519PrivateKey:
    cached = _ENC_KEYS.get(identity.agent_id)
    if cached is not None:
        return cached
    seed = identity.private_key.private_bytes(serialization.Encoding.Raw,
                                              serialization.PrivateFormat.Raw,
                                              serialization.NoEncryption())
    derived = HKDF(hashes.SHA256(), 32, salt=None, info=DERIVE_INFO).derive(seed)
    key = X25519PrivateKey.from_private_bytes(derived)
    if len(_ENC_KEYS) < 1024:
        _ENC_KEYS[identity.agent_id] = key
    return key


def enc_public_b64(identity: Identity) -> str:
    return b64(enc_private_key(identity).public_key().public_bytes(*RAW))


def aad(type_: str, sender: str, recipient: str, ref: str) -> bytes:
    return canonical_bytes({"type": type_, "from": sender, "to": recipient, "ref": ref})


def seal(data: Any, recipient_enc_key: str, aad_bytes: bytes, *,
         ephemeral: Optional[X25519PrivateKey] = None, nonce: Optional[bytes] = None) -> Dict[str, str]:
    """`ephemeral` and `nonce` are injectable for test vectors only."""
    eph = ephemeral or X25519PrivateKey.generate()
    rpk = unb64(recipient_enc_key)
    epk = eph.public_key().public_bytes(*RAW)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(rpk))
    key = HKDF(hashes.SHA256(), 32, salt=epk + rpk, info=INFO).derive(shared)
    nonce = nonce or os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, canonical_bytes(data), aad_bytes)
    return {"alg": ALG, "epk": b64(epk), "nonce": b64(nonce), "ct": b64(ct)}


def open_sealed(sealed: Any, identity: Identity, aad_bytes: bytes) -> Any:
    try:
        if not isinstance(sealed, dict) or sealed.get("alg") != ALG:
            raise ValueError("unknown algorithm")
        priv = enc_private_key(identity)
        rpk = priv.public_key().public_bytes(*RAW)
        epk = unb64(sealed["epk"])
        shared = priv.exchange(X25519PublicKey.from_public_bytes(epk))
        key = HKDF(hashes.SHA256(), 32, salt=epk + rpk, info=INFO).derive(shared)
        plain = AESGCM(key).decrypt(unb64(sealed["nonce"]), unb64(sealed["ct"]), aad_bytes)
        return json.loads(plain.decode("utf-8"))
    except (InvalidTag, ValueError, KeyError, TypeError) as exc:
        raise E.FSPError(E.BAD_SIGNATURE, f"cannot open sealed payload ({type(exc).__name__})") from None


# -- signed cards -------------------------------------------------------------------

def sign_card(card: Dict[str, Any], identity: Identity) -> Dict[str, Any]:
    body = {k: v for k, v in card.items() if k != "card_sig"}
    return {**body, "card_sig": identity.sign_digest(canonical_hash(body))}


def card_verified(card: Any) -> bool:
    """True if the card is signed by the key its agent ID is derived from."""
    try:
        if not isinstance(card, dict) or agent_id_from_pem(card["public_key"]) != card["agent_id"]:
            return False
        body = {k: v for k, v in card.items() if k != "card_sig"}
        return verify_digest(card["public_key"], canonical_hash(body), str(card.get("card_sig", "")))
    except (KeyError, ValueError, TypeError):
        return False


def enc_key_of(card: Any) -> Optional[str]:
    """The card's encryption key — only if the card signature proves it."""
    if card_verified(card) and isinstance(card.get("enc_key"), str):
        return card["enc_key"]
    return None
