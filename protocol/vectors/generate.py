"""Regenerate vectors.json from the Python reference implementation.

    python protocol/vectors/generate.py

Ed25519 signatures are deterministic, so every implementation must
reproduce these bytes exactly from the same seed.
"""

import json
from pathlib import Path

from franscor.canonical import canonical_hash, canonical_json
from franscor.envelope import digest, seal
from franscor.evidence import build_body, sign_body
from franscor.identity import Identity
from franscor.statements import make_revocation, make_rotation
from franscor import sealing
from franscor.passport import issue_passport, make_crl
from franscor.permit import issue_permit
from franscor.blackbox import AuditLog, cosign, make_checkpoint
from franscor.canonical import canonical_json as _cj
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

SEED = bytes(range(32))
SEED_NEXT = bytes(range(32, 64))
SEED_RECEIVING_HUB = bytes(range(128, 160))
CANONICAL_CASES = [
    {"b": 1, "a": [True, False, None], "é": "ü", "A": {"z": 0, "y": -1}},
    {"floats": [0.1, 1.5, 2.0, -0.000001, 1e-7, 1.5e-10, 9007199254740991.0, 123456789.125, 5e-324]},
    {"text": "line\nbreak \"quoted\" \t tab \u001f ctrl 😀 emoji"},
    [],
    "plain",
]


def build() -> dict:
    ident = Identity.from_seed(SEED)
    env = seal(ident, "task.request",
               {"task_id": "task-0001", "capability": "math.add",
                "input": {"a": 2, "b": 0.5}, "deadline_ms": 30000},
               to="fsp:" + "0" * 32, ts=1763290000000, id_="00000000-0000-4000-8000-000000000001")
    record = sign_body(build_body(agent_id=ident.agent_id, org="acme", capability="math.add",
                                  risk=2, decision="allow", rule="accepted", status="executed",
                                  task_id="task-0001", requester="fsp:" + "0" * 32,
                                  input_hash=canonical_hash({"a": 2, "b": 0.5}),
                                  response_hash=canonical_hash({"sum": 2.5}),
                                  timestamp=1763290000123,
                                  action_id="00000000-0000-4000-8000-000000000002"),
                       ident, "acme")
    vectors = {
        "fsp": "0.1",
        "seed_hex": SEED.hex(),
        "identity": {"agent_id": ident.agent_id, "kid": ident.kid, "public_key": ident.public_pem},
        "canonical": [{"value": v, "json": canonical_json(v), "sha256": canonical_hash(v)}
                      for v in CANONICAL_CASES],
        "envelope": {"value": env, "digest": digest(env)},
        "evidence": record,
        "rotation": make_rotation(ident, Identity.from_seed(SEED_NEXT), ts=1763290000456),
        "revocation": make_revocation(ident, "key compromised", ts=1763290000789),
        "enc_key": sealing.enc_public_b64(ident),
        "sealed": {
            "data": {"a": 2, "b": 0.5, "note": "é"},
            "aad": {"type": "task.request", "from": ident.agent_id, "to": "fsp:" + "0" * 32, "ref": "task-0001"},
            "ephemeral_seed_hex": bytes(range(64, 96)).hex(),
            "nonce_hex": bytes(range(12)).hex(),
            "value": sealing.seal({"a": 2, "b": 0.5, "note": "é"}, sealing.enc_public_b64(ident),
                                  sealing.aad("task.request", ident.agent_id, "fsp:" + "0" * 32, "task-0001"),
                                  ephemeral=X25519PrivateKey.from_private_bytes(bytes(range(64, 96))),
                                  nonce=bytes(range(12))),
        },
        "card": sealing.sign_card({"agent_id": ident.agent_id, "name": "vector", "org": "acme",
                                   "public_key": ident.public_pem, "enc_key": sealing.enc_public_b64(ident),
                                   "capabilities": [{"name": "math.add", "description": "add", "risk": "R1"}],
                                   "visibility": "org", "accepts": {"orgs": ["acme"], "agents": []},
                                   "runtime": {"language": "python", "version": "3", "sdk": "franscor-python/0.1.0"}},
                                  ident),
        # FSP 0.2: a passport issued by the hub whose seed is SEED_NEXT, and its CRL.
        "passport": issue_passport(Identity.from_seed(SEED_NEXT), agent_id=ident.agent_id, org="acme",
                                   agent_public_key=ident.public_pem, capabilities=["text.upper", "math.add"],
                                   ttl_ms=3_600_000, now=1763290000000, passport_id="pp_" + "ab" * 16),
        "passport_crl": make_crl(Identity.from_seed(SEED_NEXT),
                                 [{"passport_id": "pp_" + "ab" * 16, "agent_id": ident.agent_id,
                                   "revoked_at": 1763290100000, "reason": "key compromised", "ban": True}],
                                 serial=2, now=1763290200000),
    }
    # FSP 0.2: a permit from the receiving hub (SEED_RECEIVING_HUB), bound to that passport.
    vectors["permit"] = issue_permit(Identity.from_seed(SEED_RECEIVING_HUB), vectors["passport"],
                                     capabilities=["invoice.total", "fx.*"], scopes=["invoices:read"],
                                     messages=False, rate_per_min=60, max_depth=1, ttl_ms=1_800_000,
                                     now=1763290000500, permit_id="pm_" + "cd" * 16)
    # FSP 0.2 black box: 5 entries, a checkpoint at size 3 and at size 5 (receiving hub),
    # a cosignature by the SEED_NEXT hub, a partial export with proofs and consistency from 3.
    hub, witness = Identity.from_seed(SEED_RECEIVING_HUB), Identity.from_seed(SEED_NEXT)
    log = AuditLog(hub)
    for i, decision in enumerate(["allowed", "blocked", "masked", "unreachable", "allowed"]):
        text = _cj({"fsp": "0.2", "type": "audit-entry", "index": i, "ts": 1763290001000 + i,
                    "route": "inbound", "frame": "task.request", "envelope_id": f"env-{i:04d}",
                    "from": ident.agent_id, "to": "fsp:" + "0" * 32, "payload_hash": canonical_hash({"i": i}),
                    "decision": decision, **({"code": "FSP-1201"} if decision == "blocked" else {})})
        log.leaves.append(text)
        log.tree.append(text.encode("utf-8"))
        if i == 2:
            log.checkpoints.append(make_checkpoint(hub, 3, log.tree.root(3), ts=1763290002000))
    log.checkpoints.append(make_checkpoint(hub, 5, log.tree.root(5), ts=1763290003000))
    log.add_cosignature(cosign(witness, log.latest, ts=1763290003500), witness.public_pem)
    vectors["audit"] = {"checkpoint_3": log.checkpoints[0], "bundle": log.export(1, 4, since=3)}
    return vectors


if __name__ == "__main__":
    out = Path(__file__).with_name("vectors.json")
    # Bytes, not write_text: keep LF line endings on every platform.
    out.write_bytes((json.dumps(build(), indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    print(f"wrote {out}")
