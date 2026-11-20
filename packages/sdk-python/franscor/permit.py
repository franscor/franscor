"""Permits: what a partner hub's agent may do here (FSP 0.2 §2).

A permit is issued and signed by the **receiving** hub of a federation link,
bound to the passport the partner hub gave the requesting agent. It lists what
that agent may do on this side: capabilities, data scopes, a rate limit, a
maximum delegation depth and an expiry. The receiving hub checks it before
routing; the executing agent checks it again (FSP rule: the receiver
enforces).

    permit = {"fsp": "0.2", "type": "permit", "permit_id": "pm_…",
              "hub_id": "fsp:…", "hub_public_key": PEM,        # issuer = receiving hub
              "peer_hub_id": "fsp:…",                          # the partner hub
              "agent_id": "fsp:…", "passport_id": "pp_…", "org": "globex",
              "capabilities": ["invoice.total"], "scopes": ["invoices:read"],
              "messages": false, "rate_per_min": 60, "max_depth": 1,
              "issued_at": ms, "expires_at": ms, "sig": …}

Permits come from a **peering file**, the contract with each partner hub:

    {"fsp": "0.2", "type": "peering",
     "peers": [{"hub_id": "fsp:…", "name": "globex",
                "rules": [{"orgs": ["globex"], "agents": ["*"],
                           "capabilities": ["invoice.total"], "scopes": ["invoices:read"],
                           "messages": false, "rate_per_min": 60, "max_depth": 1,
                           "ttl": "1h"}]}],
     "revoked": [{"permit_id": "pm_…", "agent_id": "fsp:…", "peer_hub_id": "fsp:…",
                  "revoked_at": ms, "reason": "…"}]}

When a hub has a peering file, federated traffic is **default-deny**: a
partner's agent needs a valid passport from its hub and a permit from a
matching rule. The first matching rule wins. A revocation entry blocks its
permit and, when it names an agent, every new permit for that agent from
that peer until the entry is removed.
"""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from . import errors as E
from .canonical import canonical_hash
from .envelope import now_ms
from .identity import Identity, agent_id_from_pem, verify_digest
from .passport import DOC_VERSION, MAX_SKEW_MS

PERMIT_ID_RE = re.compile(r"^pm_[0-9a-f]{32}$")
DEFAULT_TTL_MS = 3600 * 1000
MAX_LIST = 256


def _digest(doc: Dict[str, Any]) -> str:
    return canonical_hash({k: v for k, v in doc.items() if k != "sig"})


def _fail(code: str, message: str) -> None:
    raise E.FSPError(code, message)


def _names(values: Iterable[Any]) -> List[str]:
    return sorted({str(v) for v in values})


def _match(allowed: Iterable[str], name: str) -> bool:
    """Exact name, `*` for everything, or a `prefix.*` family."""
    for pattern in allowed:
        if pattern == "*" or pattern == name:
            return True
        if pattern.endswith(".*") and name.startswith(pattern[:-1]):
            return True
    return False


# -- documents ----------------------------------------------------------------------

def issue_permit(hub: Identity, passport: Mapping[str, Any], *, capabilities: Iterable[str],
                 scopes: Iterable[str] = (), messages: bool = False, rate_per_min: int = 60,
                 max_depth: int = 0, ttl_ms: int = DEFAULT_TTL_MS, now: Optional[int] = None,
                 permit_id: Optional[str] = None) -> Dict[str, Any]:
    """Sign a permit for the holder of `passport` (already verified by the caller).

    The permit never outlives the passport it is bound to.
    """
    issued = now_ms() if now is None else now
    doc: Dict[str, Any] = {
        "fsp": DOC_VERSION, "type": "permit",
        "permit_id": permit_id or f"pm_{uuid.uuid4().hex}",
        "hub_id": hub.agent_id, "hub_public_key": hub.public_pem,
        "peer_hub_id": passport["hub_id"],
        "agent_id": passport["agent_id"], "passport_id": passport["passport_id"],
        "org": passport["org"],
        "capabilities": _names(capabilities), "scopes": _names(scopes),
        "messages": bool(messages), "rate_per_min": int(rate_per_min), "max_depth": int(max_depth),
        "issued_at": issued, "expires_at": min(issued + int(ttl_ms), int(passport["expires_at"])),
    }
    doc["sig"] = hub.sign_digest(_digest(doc))
    return doc


_FIELDS = (("permit_id", str), ("hub_id", str), ("hub_public_key", str), ("peer_hub_id", str),
           ("agent_id", str), ("passport_id", str), ("org", str), ("capabilities", list),
           ("scopes", list), ("messages", bool), ("rate_per_min", int), ("max_depth", int),
           ("issued_at", int), ("expires_at", int), ("sig", str))


def verify_permit(permit: Any, *, trusted_hubs: Optional[Mapping[str, str]] = None,
                  agent_id: Optional[str] = None, passport: Optional[Mapping[str, Any]] = None,
                  capability: Optional[str] = None, scopes: Iterable[str] = (),
                  depth: int = 0, message: bool = False,
                  revoked: Iterable[str] = (), now: Optional[int] = None) -> Dict[str, Any]:
    """Raise FSPError or return the permit.

    Codes: 1109 invalid / untrusted / foreign, 1110 expired, 1111 revoked,
    1112 the action is outside the permit (capability, scope, depth, message).
    `trusted_hubs` maps hub_id -> PEM of the hubs whose permits count (for an
    agent: its own hub). Without it, only integrity is checked.
    `passport` binds the check to the requester's (already verified) passport.
    """
    p = permit
    if not isinstance(p, dict) or p.get("type") != "permit" or p.get("fsp") != DOC_VERSION:
        _fail(E.PERMIT_INVALID, "not a permit")
    for name, kind in _FIELDS:
        value = p.get(name)
        if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
            _fail(E.PERMIT_INVALID, f"field {name!r} missing or not {kind.__name__}")
    if not PERMIT_ID_RE.match(p["permit_id"]):
        _fail(E.PERMIT_INVALID, "invalid permit_id")
    if len(p["capabilities"]) > MAX_LIST or len(p["scopes"]) > MAX_LIST \
            or not all(isinstance(x, str) for x in p["capabilities"] + p["scopes"]):
        _fail(E.PERMIT_INVALID, "malformed capability or scope list")
    if p["rate_per_min"] < 0 or p["max_depth"] < 0:
        _fail(E.PERMIT_INVALID, "negative limit")
    try:
        if agent_id_from_pem(p["hub_public_key"]) != p["hub_id"]:
            _fail(E.PERMIT_INVALID, "hub_id does not match the hub key")
    except (ValueError, TypeError):
        _fail(E.PERMIT_INVALID, "unreadable key in permit")
    if trusted_hubs is not None:
        trusted = trusted_hubs.get(p["hub_id"])
        try:
            same_key = trusted is not None and agent_id_from_pem(trusted) == p["hub_id"]
        except (ValueError, TypeError):
            same_key = False
        if not same_key:
            _fail(E.PERMIT_INVALID, "permit issued by an untrusted hub")
    if not verify_digest(p["hub_public_key"], _digest(p), p["sig"]):
        _fail(E.PERMIT_INVALID, "hub signature does not verify")
    if agent_id is not None and p["agent_id"] != agent_id:
        _fail(E.PERMIT_INVALID, "permit belongs to another agent")
    if passport is not None and (passport.get("passport_id") != p["passport_id"]
                                 or passport.get("hub_id") != p["peer_hub_id"]):
        _fail(E.PERMIT_INVALID, "permit is bound to another passport")
    current = now_ms() if now is None else now
    if p["issued_at"] > current + MAX_SKEW_MS:
        _fail(E.PERMIT_INVALID, "permit not valid yet")
    if p["expires_at"] <= current:
        _fail(E.PERMIT_EXPIRED, "permit expired")
    if p["permit_id"] in set(revoked):
        _fail(E.PERMIT_REVOKED, "permit revoked")
    if message:
        if not p["messages"]:
            _fail(E.PERMIT_DENIED, "the permit does not allow messages")
    elif capability is not None and not _match(p["capabilities"], capability):
        _fail(E.PERMIT_DENIED, f"capability {capability!r} is not in the permit")
    outside = [s for s in scopes if not _match(p["scopes"], s)]
    if outside:
        _fail(E.PERMIT_DENIED, f"scope {outside[0]!r} is not in the permit")
    if depth > p["max_depth"]:
        _fail(E.PERMIT_DENIED, f"delegation depth {depth} exceeds {p['max_depth']}")
    return p


def request_terms(body: Mapping[str, Any]) -> Tuple[List[str], int]:
    """Scopes and depth declared in a task.request body (validated)."""
    scopes = body.get("scopes", [])
    depth = body.get("depth", 0)
    if not isinstance(scopes, list) or len(scopes) > MAX_LIST or not all(isinstance(s, str) for s in scopes):
        _fail(E.MALFORMED, "scopes must be a list of strings")
    if not isinstance(depth, int) or isinstance(depth, bool) or not 0 <= depth <= 64:
        _fail(E.MALFORMED, "depth must be an integer between 0 and 64")
    return scopes, depth


# -- peering file ------------------------------------------------------------------

def _duration_ms(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value * 1000
    text = str(value).strip().lower()
    units = {"s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}
    if text and text[-1] in units:
        return int(float(text[:-1]) * units[text[-1]])
    return int(float(text) * 1000)


def _rule(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("a rule must be an object")
    caps = raw.get("capabilities", [])
    if not isinstance(caps, list) or not caps:
        raise ValueError("a rule needs a non-empty capabilities list")
    return {"orgs": list(raw.get("orgs", ["*"])), "agents": list(raw.get("agents", ["*"])),
            "capabilities": _names(caps), "scopes": _names(raw.get("scopes", [])),
            "messages": bool(raw.get("messages", False)),
            "rate_per_min": int(raw.get("rate_per_min", 60)),
            "max_depth": int(raw.get("max_depth", 0)),
            "ttl_ms": _duration_ms(raw.get("ttl", "1h"))}


def load_peering(data: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate a peering document; returns {"peers": {hub_id: {...}}, "revoked": [...]}."""
    if data.get("type") != "peering":
        raise ValueError("not a peering file (type must be 'peering')")
    peers: Dict[str, Dict[str, Any]] = {}
    for peer in data.get("peers", []):
        hub_id = peer.get("hub_id")
        if not isinstance(hub_id, str) or not hub_id.startswith("fsp:"):
            raise ValueError("each peer needs a hub_id")
        peers[hub_id] = {"name": str(peer.get("name", "")),
                         "rules": [_rule(r) for r in peer.get("rules", [])]}
    revoked = [r for r in data.get("revoked", []) if isinstance(r, dict) and r.get("permit_id")]
    return {"peers": peers, "revoked": revoked}


class _Bucket:
    """Token bucket of `rate_per_min`, refilled continuously."""

    def __init__(self, rate_per_min: int, clock):
        self.capacity = float(max(1, rate_per_min))
        self.rate = rate_per_min / 60_000.0
        self.tokens, self.stamp, self.clock = self.capacity, clock(), clock

    def take(self) -> bool:
        now = self.clock()
        self.tokens = min(self.capacity, self.tokens + (now - self.stamp) * self.rate)
        self.stamp = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class PermitOffice:
    """A hub's permit desk: reads the peering file, issues, checks and revokes permits.

    `path=None` means no peering file: federated traffic keeps FSP 0.1
    behaviour (`enforcing` is False).
    """

    def __init__(self, hub: Identity, path: "Optional[str | Path]" = None, *, clock=now_ms):
        self.hub = hub
        self.path = Path(path) if path else None
        self.clock = clock
        self.peers: Dict[str, Dict[str, Any]] = {}
        self.revoked: List[Dict[str, Any]] = []
        self.issued: Dict[Tuple[str, str], Dict[str, Any]] = {}   # (peer, passport_id) -> permit
        self._buckets: Dict[str, _Bucket] = {}
        self._raw: Dict[str, Any] = {}
        self._mtime = None
        if self.path is not None:
            if not self.path.exists():
                raise FileNotFoundError(f"peering file {self.path} not found")
            self.reload()

    @property
    def enforcing(self) -> bool:
        return self.path is not None

    def reload(self) -> bool:
        """Re-read the peering file if it changed. Cached permits are dropped so
        that edited rules apply to the next request."""
        if self.path is None or not self.path.exists():
            return False
        mtime = self.path.stat().st_mtime_ns
        if mtime == self._mtime:
            return False
        self._mtime = mtime   # a bad version is reported once, not every second
        raw = json.loads(self.path.read_text("utf-8"))
        loaded = load_peering(raw)
        self._raw = raw
        self.peers, self.revoked = loaded["peers"], loaded["revoked"]
        self._fill_revocations()   # before the cache is dropped: it knows who held which permit
        self.issued.clear()
        return True

    def _revoked_ids(self) -> set:
        return {r["permit_id"] for r in self.revoked}

    def _agent_blocked(self, peer_hub_id: str, agent_id: str) -> bool:
        return any(r.get("agent_id") == agent_id and r.get("peer_hub_id", peer_hub_id) == peer_hub_id
                   for r in self.revoked)

    def _rule_for(self, peer_hub_id: str, passport: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        peer = self.peers.get(peer_hub_id)
        for rule in (peer or {}).get("rules", []):
            if _match(rule["orgs"], passport["org"]) and _match(rule["agents"], passport["agent_id"]):
                return rule
        return None

    def permit_for(self, peer_hub_id: str, passport: Mapping[str, Any]) -> Dict[str, Any]:
        """The permit for this (verified) passport, issued on first use. Raises FSPError."""
        if peer_hub_id not in self.peers:
            _fail(E.PERMIT_DENIED, "no peering agreement with this hub")
        if self._agent_blocked(peer_hub_id, passport["agent_id"]):
            _fail(E.PERMIT_REVOKED, "this agent's permit was revoked")
        key = (peer_hub_id, passport["passport_id"])
        permit = self.issued.get(key)
        if permit is not None and permit["expires_at"] > self.clock() \
                and permit["permit_id"] not in self._revoked_ids():
            return permit
        rule = self._rule_for(peer_hub_id, passport)
        if rule is None:
            _fail(E.PERMIT_DENIED, "no peering rule covers this agent")
        permit = issue_permit(self.hub, passport, capabilities=rule["capabilities"], scopes=rule["scopes"],
                              messages=rule["messages"], rate_per_min=rule["rate_per_min"],
                              max_depth=rule["max_depth"], ttl_ms=rule["ttl_ms"], now=self.clock())
        if permit["expires_at"] <= permit["issued_at"]:
            _fail(E.PASSPORT_EXPIRED, "passport expires now")
        self.issued[key] = permit
        while len(self.issued) > 10_000:
            self.issued.pop(next(iter(self.issued)))
        return permit

    def check(self, permit: Mapping[str, Any], *, capability: Optional[str], scopes: Iterable[str],
              depth: int, message: bool = False) -> None:
        """Everything the permit bounds, plus its rate limit. Raises FSPError."""
        verify_permit(permit, trusted_hubs={self.hub.agent_id: self.hub.public_pem},
                      capability=capability, scopes=scopes, depth=depth, message=message,
                      revoked=self._revoked_ids(), now=self.clock())
        bucket_key = f"{permit['peer_hub_id']}|{permit['agent_id']}"
        bucket = self._buckets.get(bucket_key)
        if bucket is None or bucket.capacity != max(1, permit["rate_per_min"]):
            bucket = self._buckets[bucket_key] = _Bucket(permit["rate_per_min"], self.clock)
        if permit["rate_per_min"] == 0 or not bucket.take():
            _fail(E.PERMIT_DENIED, "permit rate limit reached")

    def revoke(self, permit_id: str = "", *, agent_id: str = "", peer_hub_id: str = "",
               reason: str = "unspecified") -> Dict[str, Any]:
        """Revoke now; persisted to the peering file when there is one."""
        known = next((p for p in self.issued.values() if p["permit_id"] == permit_id), None)
        if known is not None:
            agent_id = agent_id or known["agent_id"]
            peer_hub_id = peer_hub_id or known["peer_hub_id"]
        if not permit_id and not agent_id:
            raise ValueError("give a permit ID or an agent ID")
        entry = {k: v for k, v in {
            "permit_id": permit_id or f"pm_{uuid.uuid4().hex}", "agent_id": agent_id,
            "peer_hub_id": peer_hub_id, "revoked_at": self.clock(), "reason": reason[:200]}.items() if v}
        self.revoked = [r for r in self.revoked if r["permit_id"] != entry["permit_id"]] + [entry]
        self.issued = {k: p for k, p in self.issued.items()
                       if p["permit_id"] != entry["permit_id"]
                       and not (agent_id and p["agent_id"] == agent_id
                                and p["peer_hub_id"] == (peer_hub_id or p["peer_hub_id"]))}
        self._save()
        return entry

    def _fill_revocations(self) -> None:
        """A revocation written by permit ID alone: complete it with the agent, from our issuance cache."""
        changed = False
        for entry in self.revoked:
            if entry.get("agent_id"):
                continue
            known = next((p for p in self.issued.values() if p["permit_id"] == entry["permit_id"]), None)
            if known is not None:
                entry.update(agent_id=known["agent_id"], peer_hub_id=known["peer_hub_id"])
                changed = True
        if changed:
            self._save()

    def _save(self) -> None:
        if self.path is None:
            return
        raw = dict(self._raw) or {"fsp": DOC_VERSION, "type": "peering", "peers": []}
        raw["revoked"] = self.revoked
        self.path.write_bytes((json.dumps(raw, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
        self._raw = raw
        self._mtime = self.path.stat().st_mtime_ns

    def summary(self) -> Dict[str, Any]:
        """For the operator console: metadata only."""
        now = self.clock()
        return {
            "enforcing": self.enforcing,
            "peers": [{"hub_id": h, "name": p["name"], "rules": len(p["rules"])} for h, p in self.peers.items()],
            "active": [{k: p[k] for k in ("permit_id", "peer_hub_id", "agent_id", "org", "capabilities",
                                         "scopes", "rate_per_min", "max_depth", "expires_at")}
                       for p in self.issued.values() if p["expires_at"] > now][:500],
            "revoked": self.revoked[-200:],
        }


def revoke_in_file(path: Path, permit_id: str = "", *, agent_id: str = "", peer_hub_id: str = "",
                   reason: str = "unspecified") -> Dict[str, Any]:
    """Offline revocation: write to the peering file a running hub watches."""
    office = PermitOffice(Identity.generate(), path)
    return office.revoke(permit_id, agent_id=agent_id, peer_hub_id=peer_hub_id, reason=reason)
