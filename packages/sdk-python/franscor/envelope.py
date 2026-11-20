"""FSP envelopes: every frame is signed, every frame is checked.

    digest    = sha256(canonical(envelope without "sig"))   (hex)
    sig.value = b64url(Ed25519.sign(ascii(digest)))

Same scheme as InterMesh Action Evidence v0.1.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, Optional

from . import errors as E
from ._version import FSP_VERSION
from .canonical import CanonicalError, canonical_hash
from .identity import AGENT_ID_RE, Identity, agent_id_from_pem, kid_from_pem, verify_digest

MAX_SKEW_MS = 120_000

TYPES = frozenset({
    "challenge", "register", "welcome", "discover", "discover.result",
    "deliver", "routed", "message", "task.request", "task.result",
    "task.cancel", "error", "identity.rotate", "identity.revoke", "identity.ack",
    "peer.hello", "peer.sync", "peer.update", "peer.revoked", "peer.relay", "peer.status",
    "passport.trust", "passport.renew", "passport.issued", "peer.crl",
    "peer.witnessed", "peer.checkpoint", "peer.cosign",
    "operator.hello", "hub.observe", "hub.snapshot",
})
AGENT_TO_AGENT = frozenset({"message", "task.request", "task.result", "task.cancel"})


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def digest(envelope: Dict[str, Any]) -> str:
    return canonical_hash({k: v for k, v in envelope.items() if k != "sig"})


def seal(identity: Identity, type_: str, body: Dict[str, Any], *,
         to: Optional[str] = None, corr: Optional[str] = None,
         ts: Optional[int] = None, id_: Optional[str] = None) -> Dict[str, Any]:
    if type_ not in TYPES:
        raise ValueError(f"unknown FSP type {type_!r}")
    env: Dict[str, Any] = {
        "fsp": FSP_VERSION,
        "id": id_ or str(uuid.uuid4()),
        "type": type_,
        "from": identity.agent_id,
        "ts": now_ms() if ts is None else ts,
        "body": body,
    }
    if to:
        env["to"] = to
    if corr:
        env["corr"] = corr
    env["sig"] = {"alg": "Ed25519", "kid": identity.kid,
                  "value": identity.sign_digest(digest(env))}
    return env


def check_shape(env: Any) -> None:
    if not isinstance(env, dict):
        raise E.FSPError(E.MALFORMED, "frame is not a JSON object")
    if env.get("fsp") != FSP_VERSION:
        raise E.FSPError(E.UNSUPPORTED_VERSION, f"unsupported FSP version {env.get('fsp')!r}")
    for field, kind in (("id", str), ("type", str), ("from", str), ("ts", int),
                        ("body", dict), ("sig", dict)):
        value = env.get(field)
        if not isinstance(value, kind) or isinstance(value, bool):
            raise E.FSPError(E.MALFORMED, f"field {field!r} missing or not {kind.__name__}")
    if env["type"] not in TYPES:
        raise E.FSPError(E.MALFORMED, f"unknown type {env['type']!r}")
    if not AGENT_ID_RE.match(env["from"]):
        raise E.FSPError(E.MALFORMED, "invalid 'from'")
    if "to" in env and (not isinstance(env["to"], str) or not AGENT_ID_RE.match(env["to"])):
        raise E.FSPError(E.MALFORMED, "invalid 'to'")
    if not (8 <= len(env["id"]) <= 64):
        raise E.FSPError(E.MALFORMED, "invalid 'id'")


def verify(env: Dict[str, Any], public_pem: str, *, now: Optional[int] = None,
           check_time: bool = True) -> None:
    """Raise FSPError unless `env` is well-formed, fresh and signed by `public_pem`."""
    check_shape(env)
    if agent_id_from_pem(public_pem) != env["from"]:
        raise E.FSPError(E.ID_MISMATCH, "'from' does not match the signing key")
    sig = env["sig"]
    if sig.get("alg") != "Ed25519" or sig.get("kid") != kid_from_pem(public_pem):
        raise E.FSPError(E.BAD_SIGNATURE, "unexpected algorithm or key id")
    try:
        d = digest(env)
    except CanonicalError as exc:
        raise E.FSPError(E.MALFORMED, str(exc)) from None
    if not verify_digest(public_pem, d, str(sig.get("value", ""))):
        raise E.FSPError(E.BAD_SIGNATURE, "signature does not verify")
    if check_time:
        current = now_ms() if now is None else now
        if abs(current - env["ts"]) > MAX_SKEW_MS:
            raise E.FSPError(E.STALE, "timestamp outside the accepted window")
