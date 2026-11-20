"""Passports: hub-signed identity documents for agents (FSP 0.2 §3.2).

A passport says, under a hub's signature: this agent ID, of this
organization, holds this public key and these capabilities, from
`issued_at` to `expires_at`. Anyone holding the hub's public key can verify
it offline. Each hub publishes a signed revocation list (CRL).

    passport = {"fsp": "0.2", "type": "passport", "passport_id": "pp_…",
                "hub_id": "fsp:…", "hub_public_key": PEM,
                "agent_id": "fsp:…", "org": "acme", "agent_public_key": PEM,
                "capabilities": ["math.add", …], "issued_at": ms, "expires_at": ms,
                "sig": b64(Ed25519(hub, hex(sha256(canonical(passport without sig)))))}

    crl = {"fsp": "0.2", "type": "passport-crl", "hub_id": "fsp:…", "serial": n,
           "issued_at": ms, "revoked": [{"passport_id", "agent_id", "revoked_at",
           "reason", "ban"}], "sig": …}

A CRL entry with ``ban: true`` also bars the agent ID from receiving new
passports from that hub, so revocation cannot be undone by reconnecting.
"""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from . import errors as E
from .canonical import canonical_hash
from .envelope import now_ms
from .identity import Identity, agent_id_from_pem, verify_digest

DOC_VERSION = "0.2"
DEFAULT_TTL_MS = 24 * 3600 * 1000
MAX_SKEW_MS = 120_000
PASSPORT_ID_RE = re.compile(r"^pp_[0-9a-f]{32}$")


def _digest(doc: Dict[str, Any]) -> str:
    return canonical_hash({k: v for k, v in doc.items() if k != "sig"})


def _fail(code: str, message: str) -> None:
    raise E.FSPError(code, message)


# -- passports ---------------------------------------------------------------------

def issue_passport(hub: Identity, *, agent_id: str, org: str, agent_public_key: str,
                   capabilities: Iterable[str], ttl_ms: int = DEFAULT_TTL_MS,
                   now: Optional[int] = None, passport_id: Optional[str] = None) -> Dict[str, Any]:
    if agent_id_from_pem(agent_public_key) != agent_id:
        raise ValueError("agent_id does not match agent_public_key")
    issued = now_ms() if now is None else now
    doc: Dict[str, Any] = {
        "fsp": DOC_VERSION, "type": "passport",
        "passport_id": passport_id or f"pp_{uuid.uuid4().hex}",
        "hub_id": hub.agent_id, "hub_public_key": hub.public_pem,
        "agent_id": agent_id, "org": org, "agent_public_key": agent_public_key,
        "capabilities": sorted(set(capabilities)),
        "issued_at": issued, "expires_at": issued + int(ttl_ms),
    }
    doc["sig"] = hub.sign_digest(_digest(doc))
    return doc


def issue_for_card(hub: Identity, card: Mapping[str, Any], **kw) -> Dict[str, Any]:
    return issue_passport(hub, agent_id=card["agent_id"], org=card["org"],
                          agent_public_key=card["public_key"],
                          capabilities=[c["name"] for c in card.get("capabilities", [])], **kw)


def verify_passport(passport: Any, *, trusted_hubs: Optional[Mapping[str, str]] = None,
                    crls: Optional[Mapping[str, Mapping[str, Any]]] = None,
                    agent_id: Optional[str] = None, now: Optional[int] = None) -> Dict[str, Any]:
    """Raise FSPError (1106 invalid, 1107 expired, 1108 revoked) or return the passport.

    `trusted_hubs` maps hub_id -> hub public key PEM. Without it the passport is
    only checked against the key it carries: integrity, not trust — callers
    that make an authorization decision must pass trusted hubs.
    `crls` maps hub_id -> that hub's verified CRL.
    """
    p = passport
    if not isinstance(p, dict) or p.get("type") != "passport" or p.get("fsp") != DOC_VERSION:
        _fail(E.PASSPORT_INVALID, "not a passport")
    try:
        for field, kind in (("passport_id", str), ("hub_id", str), ("hub_public_key", str),
                            ("agent_id", str), ("org", str), ("agent_public_key", str),
                            ("capabilities", list), ("issued_at", int), ("expires_at", int),
                            ("sig", str)):
            if not isinstance(p.get(field), kind) or isinstance(p.get(field), bool):
                _fail(E.PASSPORT_INVALID, f"field {field!r} missing or not {kind.__name__}")
        if not PASSPORT_ID_RE.match(p["passport_id"]):
            _fail(E.PASSPORT_INVALID, "invalid passport_id")
        if agent_id_from_pem(p["hub_public_key"]) != p["hub_id"]:
            _fail(E.PASSPORT_INVALID, "hub_id does not match the hub key")
        if agent_id_from_pem(p["agent_public_key"]) != p["agent_id"]:
            _fail(E.PASSPORT_INVALID, "agent_id does not match the agent key")
    except (ValueError, TypeError):
        _fail(E.PASSPORT_INVALID, "unreadable key in passport")
    if trusted_hubs is not None:
        trusted = trusted_hubs.get(p["hub_id"])
        # Compare keys, not PEM text (line endings differ between platforms).
        try:
            same_key = trusted is not None and agent_id_from_pem(trusted) == p["hub_id"]
        except (ValueError, TypeError):
            same_key = False
        if not same_key:
            _fail(E.PASSPORT_INVALID, "passport issued by an untrusted hub")
    if not verify_digest(p["hub_public_key"], _digest(p), p["sig"]):
        _fail(E.PASSPORT_INVALID, "hub signature does not verify")
    if agent_id is not None and p["agent_id"] != agent_id:
        _fail(E.PASSPORT_INVALID, "passport belongs to another agent")
    current = now_ms() if now is None else now
    if p["issued_at"] > current + MAX_SKEW_MS:
        _fail(E.PASSPORT_INVALID, "passport not valid yet")
    if p["expires_at"] <= current:
        _fail(E.PASSPORT_EXPIRED, "passport expired")
    crl = (crls or {}).get(p["hub_id"])
    if crl is not None and crl_revokes(crl, p):
        _fail(E.PASSPORT_REVOKED, "passport revoked by its hub")
    return p


# -- revocation lists ---------------------------------------------------------------

def make_crl(hub: Identity, revoked: List[Dict[str, Any]], *, serial: int,
             now: Optional[int] = None) -> Dict[str, Any]:
    doc: Dict[str, Any] = {
        "fsp": DOC_VERSION, "type": "passport-crl", "hub_id": hub.agent_id,
        "serial": int(serial), "issued_at": now_ms() if now is None else now,
        "revoked": sorted(revoked, key=lambda r: (r["revoked_at"], r["passport_id"])),
    }
    doc["sig"] = hub.sign_digest(_digest(doc))
    return doc


def verify_crl(crl: Any, hub_public_key: str) -> Dict[str, Any]:
    if not isinstance(crl, dict) or crl.get("type") != "passport-crl" or crl.get("fsp") != DOC_VERSION:
        _fail(E.PASSPORT_INVALID, "not a passport CRL")
    try:
        if agent_id_from_pem(hub_public_key) != crl.get("hub_id"):
            _fail(E.PASSPORT_INVALID, "CRL from another hub")
    except (ValueError, TypeError):
        _fail(E.PASSPORT_INVALID, "unreadable hub key")
    if not isinstance(crl.get("serial"), int) or not isinstance(crl.get("revoked"), list):
        _fail(E.PASSPORT_INVALID, "malformed CRL")
    if not verify_digest(hub_public_key, _digest(crl), str(crl.get("sig", ""))):
        _fail(E.PASSPORT_INVALID, "CRL signature does not verify")
    return crl


def crl_revokes(crl: Mapping[str, Any], passport: Mapping[str, Any]) -> bool:
    for entry in crl.get("revoked", []):
        if entry.get("passport_id") == passport.get("passport_id"):
            return True
        if entry.get("ban") and entry.get("agent_id") == passport.get("agent_id") \
                and passport.get("issued_at", 0) <= entry.get("revoked_at", 0):
            return True
    return False


def crl_bans(crl: Mapping[str, Any], agent_id: str) -> bool:
    return any(e.get("ban") and e.get("agent_id") == agent_id for e in crl.get("revoked", []))


class PassportAuthority:
    """A hub's passport office: issues passports and maintains its signed CRL.

    The CRL is persisted to `crl_path` (JSON) when given; the file is the
    interface for offline revocation (`franscor passport revoke`), and the hub
    reloads it when it changes.
    """

    def __init__(self, hub: Identity, *, ttl_ms: int = DEFAULT_TTL_MS,
                 crl_path: "Optional[str | Path]" = None):
        self.hub = hub
        self.ttl_ms = ttl_ms
        self.crl_path = Path(crl_path) if crl_path else None
        self.issued: Dict[str, Dict[str, Any]] = {}
        self.crl = make_crl(hub, [], serial=0)
        self._mtime = None
        self.reload()

    def reload(self) -> bool:
        """Load the CRL file if it changed. Returns True when a new CRL was loaded."""
        if not self.crl_path or not self.crl_path.exists():
            return False
        mtime = self.crl_path.stat().st_mtime_ns
        if mtime == self._mtime:
            return False
        self._mtime = mtime
        crl = verify_crl(json.loads(self.crl_path.read_text("utf-8")), self.hub.public_pem)
        if crl["serial"] < self.crl["serial"]:
            raise E.FSPError(E.PASSPORT_INVALID, "CRL file is older than the CRL in memory")
        changed = crl["serial"] != self.crl["serial"]
        self.crl = crl
        return changed

    def issue(self, card: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """None if the agent is banned by this hub's CRL."""
        if crl_bans(self.crl, card["agent_id"]):
            return None
        passport = issue_for_card(self.hub, card, ttl_ms=self.ttl_ms)
        self.issued[passport["passport_id"]] = passport
        return passport

    def revoke(self, passport_id: str, *, agent_id: Optional[str] = None,
               reason: str = "unspecified", ban: bool = True) -> Dict[str, Any]:
        agent_id = agent_id or (self.issued.get(passport_id) or {}).get("agent_id")
        entry = {"passport_id": passport_id, "agent_id": agent_id or "", "revoked_at": now_ms(),
                 "reason": reason[:200], "ban": bool(ban and agent_id)}
        revoked = [e for e in self.crl["revoked"] if e["passport_id"] != passport_id] + [entry]
        self.crl = make_crl(self.hub, revoked, serial=self.crl["serial"] + 1)
        self.save()
        return self.crl

    def save(self) -> None:
        if self.crl_path:
            self.crl_path.parent.mkdir(parents=True, exist_ok=True)
            self.crl_path.write_bytes((json.dumps(self.crl, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
            self._mtime = self.crl_path.stat().st_mtime_ns


def revoke_in_file(hub: Identity, crl_path: Path, passport_id: str, *, agent_id: str = "",
                   reason: str = "unspecified", ban: bool = True) -> Dict[str, Any]:
    """Offline revocation: append to the CRL file a running hub watches."""
    authority = PassportAuthority(hub, crl_path=crl_path)
    return authority.revoke(passport_id, agent_id=agent_id or None, reason=reason, ban=ban)
