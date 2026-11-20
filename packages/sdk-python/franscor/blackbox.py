"""Black box: a hub's tamper-evident audit log (FSP 0.2 §3).

Every routing decision of a hub becomes an **entry**, a leaf of an RFC 6962
Merkle tree. The hub regularly signs a **checkpoint** ``{hub_id, tree_size,
root, ts}`` and sends it to its federated peers with a consistency proof;
each peer checks that the new tree extends the one it saw before and
returns a **cosignature**. A hub that rewrites history its peers have
witnessed is caught: the consistency proof cannot be produced, and the peer
keeps both signed checkpoints as evidence.

Entries hold metadata only — who, to whom, which frame, the hash of the
(usually encrypted) body, passport and permit IDs, the decision:

    allowed      delivered
    blocked      refused, and the sender was told so (``denied``)
    masked       refused while answering ``offline``, so as not to reveal a hidden agent
    unreachable  no such agent, or the link failed

An **export bundle** lets a third party verify entries against a signed
checkpoint (and its cosignatures) with the hub's public key only.
Leaves are stored as the exact canonical JSON text that was hashed, so a
verifier hashes bytes and never re-serializes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from . import errors as E
from .canonical import canonical_hash, canonical_json
from .envelope import now_ms
from .identity import Identity, agent_id_from_pem, verify_digest
from .merkle import MerkleTree, leaf_hash, verify_consistency, verify_inclusion
from .passport import DOC_VERSION

DECISIONS = ("allowed", "blocked", "masked", "unreachable")


class AuditError(Exception):
    """The audit log is inconsistent (local files, or a peer's history)."""


def _digest(doc: Mapping[str, Any]) -> str:
    return canonical_hash({k: v for k, v in doc.items() if k != "sig"})


def _same_key(pem: str, expected_id: str) -> bool:
    try:
        return agent_id_from_pem(pem) == expected_id
    except (ValueError, TypeError):
        return False


# -- documents ----------------------------------------------------------------------

def make_checkpoint(hub: Identity, tree_size: int, root: bytes, *, ts: Optional[int] = None) -> Dict[str, Any]:
    doc: Dict[str, Any] = {"fsp": DOC_VERSION, "type": "audit-checkpoint", "hub_id": hub.agent_id,
                           "hub_public_key": hub.public_pem, "tree_size": int(tree_size),
                           "root": root.hex(), "ts": now_ms() if ts is None else ts}
    doc["sig"] = hub.sign_digest(_digest(doc))
    return doc


def verify_checkpoint(cp: Any, hub_public_key: Optional[str] = None) -> Dict[str, Any]:
    """Raise AuditError or return the checkpoint. With `hub_public_key`, the
    issuer must be that hub (keys compared by derived ID)."""
    if not isinstance(cp, dict) or cp.get("type") != "audit-checkpoint" or cp.get("fsp") != DOC_VERSION:
        raise AuditError("not an audit checkpoint")
    for name, kind in (("hub_id", str), ("hub_public_key", str), ("tree_size", int), ("root", str),
                       ("ts", int), ("sig", str)):
        if not isinstance(cp.get(name), kind) or isinstance(cp.get(name), bool):
            raise AuditError(f"checkpoint field {name!r} missing or not {kind.__name__}")
    if cp["tree_size"] < 0 or len(cp["root"]) != 64:
        raise AuditError("malformed checkpoint")
    if not _same_key(cp["hub_public_key"], cp["hub_id"]):
        raise AuditError("checkpoint hub_id does not match its key")
    if hub_public_key is not None and not _same_key(hub_public_key, cp["hub_id"]):
        raise AuditError("checkpoint from another hub")
    if not verify_digest(cp["hub_public_key"], _digest(cp), cp["sig"]):
        raise AuditError("checkpoint signature does not verify")
    return cp


def cosign(witness: Identity, cp: Mapping[str, Any], *, ts: Optional[int] = None) -> Dict[str, Any]:
    """A witness's signature over a checkpoint it checked."""
    doc: Dict[str, Any] = {"fsp": DOC_VERSION, "type": "audit-cosignature",
                           "witness_id": witness.agent_id, "witness_public_key": witness.public_pem,
                           "hub_id": cp["hub_id"], "tree_size": cp["tree_size"], "root": cp["root"],
                           "checkpoint_ts": cp["ts"], "ts": now_ms() if ts is None else ts}
    doc["sig"] = witness.sign_digest(_digest(doc))
    return doc


def verify_cosignature(cs: Any, cp: Mapping[str, Any], witness_public_key: Optional[str] = None) -> Dict[str, Any]:
    if not isinstance(cs, dict) or cs.get("type") != "audit-cosignature" or cs.get("fsp") != DOC_VERSION:
        raise AuditError("not a cosignature")
    if any(cs.get(k) != cp.get(k) for k in ("hub_id", "tree_size", "root")) or cs.get("checkpoint_ts") != cp.get("ts"):
        raise AuditError("cosignature is for another checkpoint")
    pem = str(cs.get("witness_public_key", ""))
    if not _same_key(pem, str(cs.get("witness_id", ""))):
        raise AuditError("witness_id does not match its key")
    if witness_public_key is not None and not _same_key(witness_public_key, cs["witness_id"]):
        raise AuditError("cosignature from another witness")
    if not verify_digest(pem, _digest(cs), str(cs.get("sig", ""))):
        raise AuditError("cosignature does not verify")
    return cs


# -- the log --------------------------------------------------------------------------

class _PublicHub:
    """A hub known by its public key only: enough to read and export a log offline."""

    def __init__(self, public_pem: str):
        self.public_pem = public_pem
        self.agent_id = agent_id_from_pem(public_pem)

    def sign_digest(self, digest: str) -> str:
        raise AuditError("this log was opened read-only (no hub private key): no new checkpoint")


def open_readonly(directory: "str | Path") -> "AuditLog":
    """Open a hub's audit directory without its private key (export, inspection)."""
    path = Path(directory) / "checkpoints.jsonl"
    first = next((json.loads(line) for line in (path.read_text("utf-8").splitlines() if path.exists() else [])
                  if line.strip() and json.loads(line).get("type") == "audit-checkpoint"), None)
    if first is None:
        raise AuditError(f"{directory} has no signed checkpoint yet")
    return AuditLog(_PublicHub(first["hub_public_key"]), directory)  # type: ignore[arg-type]


class AuditLog:
    """A hub's black box. `directory=None` keeps everything in memory (tests, demos).

    Files (append-only JSON lines) in `directory`:
      entries.jsonl      leaf texts, in order
      checkpoints.jsonl  this hub's signed checkpoints and the cosignatures it received
      witnessed.jsonl    peers' checkpoints this hub checked and cosigned
      conflicts.jsonl    evidence of a peer rewriting its history
    """

    def __init__(self, hub: Identity, directory: "Optional[str | Path]" = None):
        self.hub = hub
        self.dir = Path(directory) if directory else None
        if self.dir is not None and self.dir.exists() and not self.dir.is_dir():
            raise AuditError(f"{self.dir} is not a directory")
        self.tree = MerkleTree()
        self.leaves: List[str] = []
        self.checkpoints: List[Dict[str, Any]] = []
        self.cosignatures: Dict[int, Dict[str, Dict[str, Any]]] = {}   # tree_size -> witness -> cosig
        self.witnessed: Dict[str, Dict[str, Any]] = {}                 # peer hub_id -> last checkpoint
        self.conflicts: List[Dict[str, Any]] = []
        if self.dir is not None:
            self.dir.mkdir(parents=True, exist_ok=True)
            self._load()

    # persistence
    def _lines(self, name: str) -> List[str]:
        path = self.dir / name
        return [line for line in path.read_text("utf-8").splitlines() if line.strip()] if path.exists() else []

    def _append(self, name: str, text: str) -> None:
        if self.dir is not None:
            with (self.dir / name).open("ab") as handle:
                handle.write(text.encode("utf-8") + b"\n")

    def _load(self) -> None:
        for line in self._lines("entries.jsonl"):
            self.leaves.append(line)
            self.tree.append(line.encode("utf-8"))
        for line in self._lines("checkpoints.jsonl"):
            doc = json.loads(line)
            if doc.get("type") == "audit-cosignature":
                self.cosignatures.setdefault(doc["tree_size"], {})[doc["witness_id"]] = doc
                continue
            cp = verify_checkpoint(doc, self.hub.public_pem)
            if cp["tree_size"] > len(self.tree) or self.tree.root(cp["tree_size"]).hex() != cp["root"]:
                raise AuditError(f"audit log in {self.dir} does not match its signed checkpoint "
                                 f"of size {cp['tree_size']}: entries were changed or removed")
            self.checkpoints.append(cp)
        for line in self._lines("witnessed.jsonl"):
            cp = json.loads(line)
            self.witnessed[cp["hub_id"]] = cp
        self.conflicts = [json.loads(line) for line in self._lines("conflicts.jsonl")]

    # recording
    def record(self, **fields: Any) -> Dict[str, Any]:
        if fields.get("decision") not in DECISIONS:
            raise ValueError("unknown decision")
        entry = {"fsp": DOC_VERSION, "type": "audit-entry", "index": len(self.leaves), "ts": now_ms(),
                 **{k: v for k, v in fields.items() if v is not None}}
        text = canonical_json(entry)
        self.leaves.append(text)
        self.tree.append(text.encode("utf-8"))
        self._append("entries.jsonl", text)
        return entry

    def __len__(self) -> int:
        return len(self.leaves)

    @property
    def latest(self) -> Optional[Dict[str, Any]]:
        return self.checkpoints[-1] if self.checkpoints else None

    def checkpoint(self, *, force: bool = False) -> Dict[str, Any]:
        """Sign the current tree; reuses the last checkpoint if nothing was added."""
        last = self.latest
        if last is not None and last["tree_size"] == len(self.tree) and not force:
            return last
        cp = make_checkpoint(self.hub, len(self.tree), self.tree.root())
        self.checkpoints.append(cp)
        self._append("checkpoints.jsonl", canonical_json(cp))
        return cp

    def consistency(self, from_size: int, to_size: int) -> List[str]:
        return [h.hex() for h in self.tree.consistency_proof(from_size, to_size)]

    def add_cosignature(self, cs: Any, witness_public_key: str) -> bool:
        cp = next((c for c in reversed(self.checkpoints)
                   if isinstance(cs, dict) and c["tree_size"] == cs.get("tree_size") and c["ts"] == cs.get("checkpoint_ts")),
                  None)
        if cp is None:
            return False
        verify_cosignature(cs, cp, witness_public_key)
        known = self.cosignatures.setdefault(cp["tree_size"], {})
        if cs["witness_id"] not in known:
            known[cs["witness_id"]] = cs
            self._append("checkpoints.jsonl", canonical_json(cs))
        return True

    # witnessing a peer
    def witness(self, peer_hub_id: str, peer_public_key: str, cp: Any, from_size: int,
                proof: Iterable[str]) -> Dict[str, Any]:
        """Check a peer's checkpoint against the last one we witnessed; cosign it.

        Raises AuditError on a bad signature, and records a conflict when the
        peer's new tree does not extend the one we witnessed.
        """
        verify_checkpoint(cp, peer_public_key)
        if cp["hub_id"] != peer_hub_id:
            raise AuditError("checkpoint of another hub")
        prev = self.witnessed.get(peer_hub_id)
        if prev is not None:
            if from_size != prev["tree_size"]:
                raise AuditError("stale proof: not from the size we witnessed")
            try:
                ok = verify_consistency(prev["tree_size"], cp["tree_size"], bytes.fromhex(prev["root"]),
                                        bytes.fromhex(cp["root"]), [bytes.fromhex(h) for h in proof])
            except ValueError:
                ok = False
            if not ok:
                conflict = {"fsp": DOC_VERSION, "type": "audit-conflict", "hub_id": peer_hub_id,
                            "detected_at": now_ms(), "witnessed": prev, "presented": cp,
                            "proof": list(proof)}
                self.conflicts.append(conflict)
                self._append("conflicts.jsonl", canonical_json(conflict))
                raise AuditError(f"hub {peer_hub_id} presented a history that does not extend the one "
                                 f"witnessed at size {prev['tree_size']}")
            if cp["tree_size"] == prev["tree_size"] and cp["ts"] == prev["ts"]:
                return cosign(self.hub, cp)
        self.witnessed[peer_hub_id] = cp
        self._append("witnessed.jsonl", canonical_json(cp))
        return cosign(self.hub, cp)

    # export
    def export(self, start: int = 0, end: Optional[int] = None, *,
               since: Optional[int] = None) -> Dict[str, Any]:
        """Bundle for a third party: the latest checkpoint, its cosignatures, entries
        [start, end) with inclusion proofs (omitted for a full export), and, with
        `since`, a consistency proof from an earlier tree size."""
        cp = self.latest or self.checkpoint()
        size = cp["tree_size"]
        end = size if end is None else min(end, size)
        if not 0 <= start <= end:
            raise ValueError("bad range")
        full = start == 0 and end == size
        bundle: Dict[str, Any] = {
            "fsp": DOC_VERSION, "type": "audit-bundle", "hub_id": self.hub.agent_id,
            "hub_public_key": self.hub.public_pem, "checkpoint": cp,
            "cosignatures": list(self.cosignatures.get(size, {}).values()),
            "entries": [{"index": i, "leaf": self.leaves[i]} for i in range(start, end)],
        }
        if not full:
            bundle["proofs"] = {str(i): [h.hex() for h in self.tree.inclusion_proof(i, size)]
                                for i in range(start, end)}
        if since is not None:
            older = next((c for c in self.checkpoints if c["tree_size"] == since), None)
            bundle["consistency"] = {"from_size": since,
                                     "from_checkpoint": older,
                                     "proof": self.consistency(since, size)}
        return bundle

    def summary(self) -> Dict[str, Any]:
        cp = self.latest
        return {
            "enabled": True, "persistent": self.dir is not None, "tree_size": len(self.tree),
            "checkpoint": {k: cp[k] for k in ("tree_size", "root", "ts")} if cp else None,
            "cosigned_by": sorted(self.cosignatures.get(cp["tree_size"], {})) if cp else [],
            "witnessing": {h: c["tree_size"] for h, c in self.witnessed.items()},
            "conflicts": [{"hub_id": c["hub_id"], "detected_at": c["detected_at"],
                           "witnessed_size": c["witnessed"]["tree_size"],
                           "presented_size": c["presented"]["tree_size"]} for c in self.conflicts],
        }


# -- third-party verification -----------------------------------------------------------

def verify_bundle(bundle: Any, *, hub_public_key: Optional[str] = None,
                  witness_keys: Optional[Mapping[str, str]] = None,
                  previous: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Check an export bundle. Returns a report; `valid` is False on any failure.

    * `hub_public_key`: the hub's key obtained independently (otherwise only
      integrity is checked, against the key the bundle carries);
    * `witness_keys`: witness_id -> PEM of peers whose cosignatures count;
    * `previous`: an earlier checkpoint of the same hub (e.g. from an older
      bundle): the bundle must prove the new tree extends it.
    """
    report: Dict[str, Any] = {"valid": False, "errors": [], "entries": 0, "witnesses": [],
                              "issuer_checked": hub_public_key is not None}
    try:
        if not isinstance(bundle, dict) or bundle.get("type") != "audit-bundle":
            raise AuditError("not an audit bundle")
        cp = verify_checkpoint(bundle.get("checkpoint"), hub_public_key or str(bundle.get("hub_public_key", "")))
        if cp["hub_id"] != bundle.get("hub_id"):
            raise AuditError("bundle and checkpoint name different hubs")
        report.update(hub_id=cp["hub_id"], tree_size=cp["tree_size"], root=cp["root"], checkpoint_ts=cp["ts"])
        size, root = cp["tree_size"], bytes.fromhex(cp["root"])
        entries = bundle.get("entries") or []
        indexes = [e.get("index") for e in entries]
        if indexes and (not all(isinstance(i, int) and not isinstance(i, bool) for i in indexes)
                        or indexes != list(range(indexes[0], indexes[0] + len(indexes)))
                        or indexes[0] < 0 or indexes[-1] >= size):
            raise AuditError("entries must be consecutive indexes of the signed tree")
        proofs = bundle.get("proofs")
        if proofs is None:
            if indexes != list(range(size)):
                raise AuditError("a bundle without proofs must hold every entry")
            tree = MerkleTree()
            for e in entries:
                tree.append(str(e["leaf"]).encode("utf-8"))
            if tree.root() != root:
                raise AuditError("entries do not produce the signed root")
        for e in entries:
            leaf = str(e["leaf"])
            doc = json.loads(leaf)
            if canonical_json(doc) != leaf or doc.get("index") != e["index"] or doc.get("type") != "audit-entry":
                raise AuditError(f"entry {e['index']} is not a canonical audit entry")
            if proofs is not None:
                proof = [bytes.fromhex(h) for h in proofs.get(str(e["index"]), [])]
                if not verify_inclusion(leaf_hash(leaf.encode("utf-8")), e["index"], size, proof, root):
                    raise AuditError(f"entry {e['index']} is not in the signed tree")
        report["entries"] = len(entries)
        for cs in bundle.get("cosignatures") or []:
            wid = cs.get("witness_id") if isinstance(cs, dict) else None
            if witness_keys is not None and wid not in witness_keys:
                continue
            try:
                verify_cosignature(cs, cp, (witness_keys or {}).get(wid))
                report["witnesses"].append(wid)
            except AuditError as exc:
                report["errors"].append(f"cosignature of {wid}: {exc}")
        if previous is not None:
            prev = verify_checkpoint(previous, hub_public_key or cp["hub_public_key"])
            cons = bundle.get("consistency") or {}
            if prev["tree_size"] != cons.get("from_size"):
                raise AuditError("the bundle has no consistency proof from the previous checkpoint")
            if not verify_consistency(prev["tree_size"], size, bytes.fromhex(prev["root"]), root,
                                      [bytes.fromhex(h) for h in cons.get("proof", [])]):
                raise AuditError("history was rewritten since the previous checkpoint")
            report["extends_previous"] = True
        report["valid"] = not report["errors"]
    except (AuditError, ValueError, KeyError, TypeError, E.FSPError) as exc:
        report["errors"].append(str(exc))
    return report
