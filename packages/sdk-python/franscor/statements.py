"""Identity statements: key rotation and key revocation (FSP 0.1 §2.1).

Both are portable signed JSON objects, verifiable offline, by anyone:

* **rotation** — signed by the old key *and* the new key. The old signature
  proves the owner authorized the change; the new one proves possession of
  the new key (no one can rotate someone else's ID onto their key).
* **revocation** — signed by the key being revoked. Self-revocation is the
  only kind that needs no authority; org-level revocation by an endorsing
  key is planned with the control plane.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from . import errors as E
from ._version import FSP_VERSION
from .canonical import canonical_hash
from .envelope import now_ms
from .identity import Identity, agent_id_from_pem, verify_digest

ROTATION = "key-rotation"
REVOCATION = "key-revocation"
MAX_REASON = 200


def _digest(statement: Dict[str, Any], sig_field: str) -> str:
    return canonical_hash({k: v for k, v in statement.items() if k != sig_field})


def make_rotation(old: Identity, new: Identity, *, ts: Optional[int] = None) -> Dict[str, Any]:
    st: Dict[str, Any] = {
        "fsp": FSP_VERSION, "type": ROTATION,
        "old_agent_id": old.agent_id, "old_public_key": old.public_pem,
        "new_agent_id": new.agent_id, "new_public_key": new.public_pem,
        "ts": now_ms() if ts is None else ts,
    }
    digest = _digest(st, "sigs")
    st["sigs"] = {"old": old.sign_digest(digest), "new": new.sign_digest(digest)}
    return st


def make_revocation(identity: Identity, reason: str = "unspecified", *,
                    ts: Optional[int] = None) -> Dict[str, Any]:
    st: Dict[str, Any] = {
        "fsp": FSP_VERSION, "type": REVOCATION,
        "agent_id": identity.agent_id, "public_key": identity.public_pem,
        "reason": reason[:MAX_REASON], "ts": now_ms() if ts is None else ts,
    }
    st["sig"] = identity.sign_digest(_digest(st, "sig"))
    return st


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise E.FSPError(E.BAD_SIGNATURE, message)


def verify_rotation(st: Any) -> None:
    _require(isinstance(st, dict) and st.get("type") == ROTATION and st.get("fsp") == FSP_VERSION,
             "not a key-rotation statement")
    try:
        _require(agent_id_from_pem(st["old_public_key"]) == st["old_agent_id"], "old id does not match old key")
        _require(agent_id_from_pem(st["new_public_key"]) == st["new_agent_id"], "new id does not match new key")
    except (KeyError, ValueError, TypeError):
        raise E.FSPError(E.MALFORMED, "rotation statement is incomplete") from None
    _require(st["old_agent_id"] != st["new_agent_id"], "rotation to the same key")
    _require(isinstance(st.get("ts"), int) and not isinstance(st.get("ts"), bool), "ts must be an integer")
    sigs = st.get("sigs") or {}
    digest = _digest(st, "sigs")
    _require(verify_digest(st["old_public_key"], digest, str(sigs.get("old", ""))), "old key signature invalid")
    _require(verify_digest(st["new_public_key"], digest, str(sigs.get("new", ""))), "new key signature invalid")


def verify_revocation(st: Any) -> None:
    _require(isinstance(st, dict) and st.get("type") == REVOCATION and st.get("fsp") == FSP_VERSION,
             "not a key-revocation statement")
    try:
        _require(agent_id_from_pem(st["public_key"]) == st["agent_id"], "id does not match key")
    except (KeyError, ValueError, TypeError):
        raise E.FSPError(E.MALFORMED, "revocation statement is incomplete") from None
    _require(isinstance(st.get("ts"), int) and not isinstance(st.get("ts"), bool), "ts must be an integer")
    _require(isinstance(st.get("reason"), str) and len(st["reason"]) <= MAX_REASON, "bad reason")
    _require(verify_digest(st["public_key"], _digest(st, "sig"), str(st.get("sig", ""))), "signature invalid")


def revoked_id(st: Dict[str, Any]) -> str:
    """The agent ID a verified statement takes out of service."""
    return st["old_agent_id"] if st["type"] == ROTATION else st["agent_id"]


def verify_statement(st: Any) -> None:
    if isinstance(st, dict) and st.get("type") == ROTATION:
        verify_rotation(st)
    else:
        verify_revocation(st)
