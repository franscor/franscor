"""Signed, chained evidence of every task decision.

The record format *is* InterMesh Action Evidence v0.1
(`specs/action-evidence-v0.md`): `intermesh verify` checks FRANSCOR
evidence unchanged. Inputs and outputs are never stored, only hashes.
"""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .canonical import canonical_hash
from .envelope import now_ms
from .identity import Identity, kid_from_pem, verify_digest

SPEC_VERSION = "0.1"
GENESIS = "0" * 64
REQUIRED = ("version", "action_id", "timestamp", "agent_id", "organization_id",
            "action", "risk", "authorization", "execution", "prev_hash")


def _clean(data: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in data.items() if v is not None}


def build_body(*, agent_id: str, org: str, capability: str, risk: int,
               decision: str, rule: str, status: str, task_id: str,
               requester: str, input_hash: Optional[str],
               response_hash: Optional[str] = None, prev_hash: str = GENESIS,
               timestamp: Optional[int] = None,
               action_id: Optional[str] = None,
               passport_id: Optional[str] = None,
               permit_id: Optional[str] = None) -> Dict[str, Any]:
    return {
        "version": SPEC_VERSION,
        "action_id": action_id or str(uuid.uuid4()),
        "timestamp": now_ms() if timestamp is None else timestamp,
        "agent_id": agent_id,
        "organization_id": org,
        "action": _clean({"method": "TASK", "target": f"fsp://{capability}",
                          "type": "fsp.task", "payload_hash": input_hash}),
        "risk": {"level": f"R{risk}", "label": f"R{risk}", "value": risk},
        "authorization": {"policy": "franscor-agent", "rule": rule, "decision": decision},
        "execution": _clean({"status": status, "task_id": task_id,
                             "requester": requester, "response_hash": response_hash,
                             "passport_id": passport_id, "permit_id": permit_id}),
        "prev_hash": prev_hash,
    }


def sign_body(body: Dict[str, Any], identity: Identity, issuer: str) -> Dict[str, Any]:
    digest = canonical_hash(body)
    return {**body, "evidence": {
        "hash": digest, "algorithm": "Ed25519",
        "signature": identity.sign_digest(digest), "issuer": issuer,
        "public_key": identity.public_pem, "key_fingerprint": identity.kid}}


class EvidenceLog:
    """Append-only JSONL chain. Resumes `prev_hash` from the last line."""

    def __init__(self, path: Path, identity: Identity, issuer: str):
        self.path = Path(path)
        self.identity = identity
        self.issuer = issuer
        self._lock = threading.Lock()
        self.prev_hash = GENESIS
        if self.path.exists():
            last = None
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        last = line
            if last:
                self.prev_hash = json.loads(last)["evidence"]["hash"]

    def append(self, **fields: Any) -> Dict[str, Any]:
        with self._lock:
            body = build_body(prev_hash=self.prev_hash, **fields)
            record = sign_body(body, self.identity, self.issuer)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            self.prev_hash = record["evidence"]["hash"]
            return record


@dataclass
class Report:
    valid: bool = False
    errors: List[str] = field(default_factory=list)
    count: int = 0

    def to_dict(self) -> dict:
        return {"valid": self.valid, "count": self.count, "errors": self.errors}


def verify_record(record: Any, trusted_pem: Optional[str] = None) -> Report:
    report = Report(count=1)
    if not isinstance(record, dict) or not isinstance(record.get("evidence"), dict):
        report.errors.append("not an evidence record")
        return report
    missing = [f for f in REQUIRED if f not in record]
    if missing:
        report.errors.append(f"missing fields: {missing}")
        return report
    env = record["evidence"]
    digest = canonical_hash({f: record[f] for f in REQUIRED})
    if digest != env.get("hash"):
        report.errors.append("content does not match its hash (modified)")
        return report
    pem = trusted_pem or env.get("public_key")
    if not pem:
        report.errors.append("no public key")
        return report
    if trusted_pem and env.get("key_fingerprint") != kid_from_pem(trusted_pem):
        report.errors.append("signed by a different key than the trusted one")
        return report
    if not verify_digest(pem, digest, str(env.get("signature", ""))):
        report.errors.append("bad signature")
        return report
    report.valid = True
    return report


def verify_chain(records: List[Dict[str, Any]], trusted_pem: Optional[str] = None) -> Report:
    report = Report(valid=True, count=len(records))
    previous = GENESIS
    for i, record in enumerate(records):
        single = verify_record(record, trusted_pem)
        if not single.valid:
            report.valid = False
            report.errors.extend(f"#{i}: {e}" for e in single.errors)
            continue
        if record["prev_hash"] != previous:
            report.valid = False
            report.errors.append(f"#{i}: broken chain (record removed or inserted)")
        previous = record["evidence"]["hash"]
    return report


def read_log(path: Path) -> List[Dict[str, Any]]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]
