"""Black box (FSP 0.2 §3): Merkle audit log of every routing decision, signed
checkpoints witnessed by peer hubs, export bundles verified by a third party —
and the attacks it must expose: edited entries, re-signed history, forged
checkpoints, tampered bundles."""

import asyncio
import json
import os
import subprocess
import sys

import pytest

import franscor
from franscor import errors as E
from franscor.blackbox import (AuditError, AuditLog, cosign, make_checkpoint, open_readonly,
                               verify_bundle, verify_checkpoint, verify_cosignature)
from franscor.canonical import canonical_json
from franscor.capabilities import Capability, clear_registry
from franscor.hub import Hub
from franscor.identity import Identity
from franscor.merkle import EMPTY_ROOT, MerkleTree, leaf_hash, verify_consistency, verify_inclusion

HUB = Identity.generate()
PEER = Identity.generate()


@pytest.fixture(autouse=True)
def _clean():
    clear_registry()
    yield
    clear_registry()


# -- Merkle tree ---------------------------------------------------------------------

def test_merkle_roots_match_rfc6962_reference_values():
    t = MerkleTree()
    for h in ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]:
        t.append(bytes.fromhex(h))
    assert t.root(0) == EMPTY_ROOT
    assert t.root(1).hex() == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    assert t.root(7).hex() == "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c"
    assert t.root(8).hex() == "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"


def test_merkle_proofs_hold_and_reject_tampering():
    t = MerkleTree()
    for i in range(21):
        t.append(str(i).encode())
    for n in range(1, 22):
        for i in range(n):
            proof = t.inclusion_proof(i, n)
            assert verify_inclusion(t.leaves[i], i, n, proof, t.root(n))
            assert not verify_inclusion(leaf_hash(b"forged"), i, n, proof, t.root(n))
        for m in range(n + 1):
            proof = t.consistency_proof(m, n)
            assert verify_consistency(m, n, t.root(m), t.root(n), proof)
            if 0 < m < n:
                assert not verify_consistency(m, n, leaf_hash(b"other history"), t.root(n), proof)


# -- documents and the log -----------------------------------------------------------

def fill(log, n, start=0):
    for i in range(start, start + n):
        log.record(route="local", frame="task.request", envelope_id=f"env-{i}", payload_hash="ab" * 32,
                   decision=("allowed", "blocked", "masked", "unreachable")[i % 4], **{"from": "fsp:a", "to": "fsp:b"})


def test_checkpoint_and_cosignature_verify_and_resist_forgery():
    log = AuditLog(HUB)
    fill(log, 5)
    cp = log.checkpoint()
    assert verify_checkpoint(cp, HUB.public_pem)["tree_size"] == 5
    with pytest.raises(AuditError):
        verify_checkpoint(cp, PEER.public_pem)                       # from another hub
    with pytest.raises(AuditError):
        verify_checkpoint({**cp, "root": "00" * 32}, HUB.public_pem)  # tampered root
    forged = make_checkpoint(PEER, 5, bytes(32))
    forged["hub_id"], forged["hub_public_key"] = HUB.agent_id, HUB.public_pem
    with pytest.raises(AuditError):
        verify_checkpoint(forged, HUB.public_pem)                     # signed by another key
    cs = cosign(PEER, cp)
    assert verify_cosignature(cs, cp, PEER.public_pem)
    with pytest.raises(AuditError):
        verify_cosignature(cs, {**cp, "tree_size": 6})                # for another checkpoint
    assert log.checkpoint() is cp                                    # nothing new: same checkpoint


def test_full_and_partial_exports_verify_with_the_hub_key():
    log = AuditLog(HUB)
    fill(log, 9)
    log.checkpoint()
    log.add_cosignature(cosign(PEER, log.latest), PEER.public_pem)
    full = log.export()
    report = verify_bundle(full, hub_public_key=HUB.public_pem, witness_keys={PEER.agent_id: PEER.public_pem})
    assert report["valid"] and report["entries"] == 9 and report["witnesses"] == [PEER.agent_id]
    part = log.export(3, 6)
    assert set(part["proofs"]) == {"3", "4", "5"}
    assert verify_bundle(part, hub_public_key=HUB.public_pem)["valid"]
    # Not who it claims: another hub's key.
    assert not verify_bundle(full, hub_public_key=PEER.public_pem)["valid"]


def _tampered(bundle, how):
    b = json.loads(json.dumps(bundle))
    if how == "decision":
        e = json.loads(b["entries"][2]["leaf"])
        e["decision"] = "allowed" if e["decision"] != "allowed" else "blocked"
        b["entries"][2]["leaf"] = canonical_json(e)
    elif how == "removed":
        del b["entries"][4]
    elif how == "swapped":
        b["entries"][1]["leaf"], b["entries"][2]["leaf"] = b["entries"][2]["leaf"], b["entries"][1]["leaf"]
    elif how == "proof":
        b["proofs"]["4"][0] = "00" * 32
    elif how == "index":
        b["entries"][0]["index"] = 1
    elif how == "non-canonical":
        b["entries"][0]["leaf"] = b["entries"][0]["leaf"].replace(",", ", ", 1)
    return b


@pytest.mark.parametrize("how", ["decision", "removed", "swapped", "index", "non-canonical"])
def test_tampered_full_bundle_is_rejected(how):
    log = AuditLog(HUB)
    fill(log, 7)
    log.checkpoint()
    assert not verify_bundle(_tampered(log.export(), how), hub_public_key=HUB.public_pem)["valid"]


@pytest.mark.parametrize("how", ["decision", "proof"])
def test_tampered_partial_bundle_is_rejected(how):
    log = AuditLog(HUB)
    fill(log, 9)
    log.checkpoint()
    assert not verify_bundle(_tampered(log.export(2, 7), how), hub_public_key=HUB.public_pem)["valid"]


def test_bundle_proves_history_was_extended_not_rewritten():
    log = AuditLog(HUB)
    fill(log, 4)
    first = log.export()
    fill(log, 3, start=4)
    log.checkpoint()
    later = log.export(since=4)
    report = verify_bundle(later, hub_public_key=HUB.public_pem, previous=first["checkpoint"])
    assert report["valid"] and report["extends_previous"]
    # The same key, a different past: the consistency proof cannot be produced.
    other = AuditLog(HUB)
    fill(other, 1)
    other.record(route="local", frame="message", envelope_id="rewritten", payload_hash="00" * 32,
                 decision="allowed", **{"from": "fsp:a", "to": "fsp:b"})
    fill(other, 5, start=2)
    other.checkpoint()
    assert not verify_bundle(other.export(since=4), hub_public_key=HUB.public_pem, previous=first["checkpoint"])["valid"]


def test_edited_log_on_disk_is_refused_at_start(tmp_path):
    log = AuditLog(HUB, tmp_path / "audit")
    fill(log, 5)
    log.checkpoint()
    assert len(AuditLog(HUB, tmp_path / "audit")) == 5                     # reopens cleanly
    path = tmp_path / "audit" / "entries.jsonl"
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0].replace('"blocked"', '"allowed"').replace('"allowed"', '"masked"')]
                              + lines[1:]) + "\n")
    with pytest.raises(AuditError):
        AuditLog(HUB, tmp_path / "audit")
    path.write_text("\n".join(lines[:3]) + "\n")                           # entries removed
    with pytest.raises(AuditError):
        AuditLog(HUB, tmp_path / "audit")


def test_witness_records_a_conflict_when_history_is_rewritten():
    origin, witness = AuditLog(HUB), AuditLog(PEER)
    fill(origin, 4)
    cp = origin.checkpoint()
    witness.witness(HUB.agent_id, HUB.public_pem, cp, 0, [])
    rewritten = AuditLog(HUB)
    fill(rewritten, 4, start=10)
    fill(rewritten, 2, start=20)
    cp2 = rewritten.checkpoint()
    with pytest.raises(AuditError):
        witness.witness(HUB.agent_id, HUB.public_pem, cp2, 4, rewritten.consistency(4, 6))
    conflict = witness.conflicts[0]
    # Both checkpoints are validly signed by the hub: a third party can check the evidence.
    verify_checkpoint(conflict["witnessed"], HUB.public_pem)
    verify_checkpoint(conflict["presented"], HUB.public_pem)
    # An honest extension is cosigned.
    fill(origin, 2, start=4)
    cs = witness.witness(HUB.agent_id, HUB.public_pem, origin.checkpoint(), 4, origin.consistency(4, 6))
    assert cs["tree_size"] == 6


# -- hubs ----------------------------------------------------------------------------

async def until(predicate, timeout=5.0):
    for _ in range(int(timeout / 0.02)):
        if predicate():
            return True
        await asyncio.sleep(0.02)
    raise AssertionError("condition not reached")


async def make(hub, tmp_path, name, caps=(), **kw):
    kw.setdefault("load_plugins", False)
    kw.setdefault("reconnect", False)
    return await franscor.connect(name, hub_url=hub.url, home=tmp_path / name, tools=list(caps), **kw)


def decisions(hub):
    return [json.loads(leaf) for leaf in hub.audit.leaves]


async def test_every_routing_decision_is_audited_and_witnessed(tmp_path):
    a_id, b_id = Identity.generate(), Identity.generate()
    peering = tmp_path / "peering.json"
    peering.write_text(json.dumps({"fsp": "0.2", "type": "peering", "peers": [{
        "hub_id": a_id.agent_id, "rules": [{"orgs": ["globex"], "capabilities": ["fx.rate"]}]}]}))
    b = await Hub("127.0.0.1", 0, identity=b_id, allowed_peers=[a_id.agent_id], audit=True, peering=peering,
                  checkpoint_interval=3600).start()
    a = await Hub("127.0.0.1", 0, identity=a_id, allowed_peers=[b_id.agent_id], peers=[b.url], audit=True,
                  checkpoint_interval=3600).start()
    await until(lambda: a_id.agent_id in b.links and b_id.agent_id in a.links)
    worker = await make(b, tmp_path, "worker", [Capability("fx.rate", lambda pair: {"pair": pair}, risk="R1"),
                                                Capability("fx.trade", lambda pair: {}, risk="R1")],
                        org="acme", visibility="public", accept_orgs=["acme", "globex"])
    hidden = await make(b, tmp_path, "hidden", [Capability("fx.rate", lambda pair: {}, risk="R1")], org="acme")
    picky = await make(b, tmp_path, "picky", [Capability("fx.rate", lambda pair: {}, risk="R1")], org="acme",
                       visibility="public")   # visible to globex, accepts acme only
    boss = await make(a, tmp_path, "boss", org="globex")
    stranger = await make(b, tmp_path, "stranger", org="initech")
    try:
        await until(lambda: worker.agent_id in a.remote and picky.agent_id in a.remote)
        await boss.delegate("fx.rate", {"pair": "EUR/USD-SECRET"}, to=worker.agent_id)
        attempts = [(boss, "fx.trade", worker.agent_id, E.DENIED),      # refused by B: not in the permit
                    (boss, "fx.rate", hidden.agent_id, E.OFFLINE),       # never shared: A cannot route it
                    (boss, "fx.rate", picky.agent_id, E.DENIED),         # refused by A's own check
                    (boss, "fx.rate", "fsp:" + "0" * 32, E.OFFLINE),     # nobody
                    (stranger, "fx.rate", hidden.agent_id, E.OFFLINE)]   # exists, hidden: masked on B
        for agent, cap, target, code in attempts:
            with pytest.raises(franscor.TaskError) as err:
                await agent.delegate(cap, {"pair": "x"}, to=target, timeout=3, retries=0)
            assert err.value.code == code
        inbound = [(e["to"], e["decision"], e.get("code")) for e in decisions(b)
                   if e["route"] == "inbound" and e["frame"] == "task.request"]
        assert inbound == [(worker.agent_id, "allowed", None), (worker.agent_id, "blocked", E.PERMIT_DENIED)]
        outbound = [e["decision"] for e in decisions(a) if e["route"] == "outbound" and e["frame"] == "task.request"]
        assert outbound == ["allowed", "blocked", "blocked"]
        # Unknown to A (not shared, or nobody): nowhere to route. Hidden on B: masked.
        local = [(e["decision"]) for e in decisions(a) + decisions(b)
                 if e["route"] == "local" and e["frame"] == "task.request"]
        assert local == ["unreachable", "unreachable", "masked"]
        req = next(e for e in decisions(b) if e["decision"] == "allowed" and e["frame"] == "task.request")
        assert req["passport_id"] == boss.passport["passport_id"] and req["peer_hub_id"] == a_id.agent_id
        assert req["permit_id"].startswith("pm_") and len(req["payload_hash"]) == 64
        assert "EUR/USD-SECRET" not in "\n".join(b.audit.leaves + a.audit.leaves)   # metadata only
        # Checkpoints are witnessed by the peer.
        cp = await b.checkpoint()
        await until(lambda: a_id.agent_id in b.audit.cosignatures.get(cp["tree_size"], {}))
        bundle = b.audit.export()
        report = verify_bundle(bundle, hub_public_key=b_id.public_pem,
                               witness_keys={a_id.agent_id: a_id.public_pem})
        assert report["valid"] and report["witnesses"] == [a_id.agent_id]
        snap = b.snapshot()["audit"]
        assert snap["cosigned_by"] == [a_id.agent_id] and snap["recent"][-1]["index"] == len(b.audit) - 1
        assert a.snapshot()["audit"]["witnessing"] == {b_id.agent_id: cp["tree_size"]}
    finally:
        for agent in (stranger, boss, picky, hidden, worker):
            await agent.close()
        await a.stop()
        await b.stop()


async def test_peer_detects_a_hub_that_rewrites_witnessed_history(tmp_path):
    """The hub operator has the hub key and edits the log, re-signing every checkpoint.
    The hub restarts happily — but its peer witnessed the old tree and catches it."""
    a_id, b_id = Identity.generate(), Identity.generate()
    audit_a = tmp_path / "audit-a"
    b = await Hub("127.0.0.1", 0, identity=b_id, allowed_peers=[a_id.agent_id], audit=tmp_path / "audit-b",
                  checkpoint_interval=3600).start()

    async def start_a():
        hub = await Hub("127.0.0.1", 0, identity=a_id, allowed_peers=[b_id.agent_id], peers=[b.url],
                        audit=audit_a, checkpoint_interval=3600).start()
        await until(lambda: a_id.agent_id in b.links and b_id.agent_id in hub.links)
        return hub

    a = await start_a()
    agent = await make(a, tmp_path, "worker", [Capability("x.y", lambda: {}, risk="R1")], org="acme")
    other = await make(a, tmp_path, "other", org="acme")
    try:
        await other.delegate("x.y", {}, to=agent.agent_id)
        with pytest.raises(franscor.TaskError):
            await other.delegate("x.y", {}, to="fsp:" + "1" * 32, timeout=3, retries=0)
        cp = await a.checkpoint()
        await until(lambda: b_id.agent_id in a.audit.cosignatures.get(cp["tree_size"], {}))
        assert b.audit.witnessed[a_id.agent_id]["tree_size"] == cp["tree_size"]
    finally:
        await other.close()
        await agent.close()
        await a.stop()
    await until(lambda: a_id.agent_id not in b.links)

    # Rewrite: turn the "unreachable" entry into an "allowed" one, then re-sign everything.
    entries = [json.loads(line) for line in (audit_a / "entries.jsonl").read_text().splitlines()]
    for e in entries:
        if e["decision"] == "unreachable":
            e["decision"] = "allowed"
    forged = AuditLog(a_id)
    for e in entries:
        text = canonical_json(e)
        forged.leaves.append(text)
        forged.tree.append(text.encode())
    (audit_a / "entries.jsonl").write_text("".join(t + "\n" for t in forged.leaves))
    (audit_a / "checkpoints.jsonl").write_text(canonical_json(forged.checkpoint()) + "\n")

    a = await start_a()   # internally consistent again: the hub starts
    try:
        await until(lambda: b.audit.conflicts, timeout=5)
        conflict = b.audit.conflicts[0]
        assert conflict["hub_id"] == a_id.agent_id
        assert conflict["witnessed"]["root"] != conflict["presented"]["root"]
        assert b.snapshot()["audit"]["conflicts"][0]["hub_id"] == a_id.agent_id
        # The conflict survives a restart of the witness (it is on disk).
        assert open_readonly(tmp_path / "audit-b").conflicts[0]["presented"]["root"] == conflict["presented"]["root"]
    finally:
        await a.stop()
        await b.stop()


def test_hub_without_audit_keeps_fsp01_behaviour():
    hub = Hub("127.0.0.1", 0)
    assert hub.audit is None and hub.snapshot()["audit"] == {"enabled": False}


def test_cli_show_export_and_verify(tmp_path):
    log = AuditLog(HUB, tmp_path / "audit")
    fill(log, 6)
    log.checkpoint()
    log.add_cosignature(cosign(PEER, log.latest), PEER.public_pem)
    (tmp_path / "hub.pem").write_text(HUB.public_pem)
    (tmp_path / "peer.pem").write_text(PEER.public_pem)
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}

    def run(*args):
        return subprocess.run([sys.executable, "-m", "franscor.cli", "audit", *args],
                              capture_output=True, text=True, env=env)

    shown = run("show", str(tmp_path / "audit"))
    assert shown.returncode == 0 and "entries 6" in shown.stdout and PEER.agent_id in shown.stdout
    assert run("export", str(tmp_path / "audit"), "--out", str(tmp_path / "bundle.json")).returncode == 0
    ok = run("verify", str(tmp_path / "bundle.json"), "--hub-key", str(tmp_path / "hub.pem"),
             "--witness-key", str(tmp_path / "peer.pem"))
    report = json.loads(ok.stdout)
    assert ok.returncode == 0 and report["valid"] and report["witnesses"] == [PEER.agent_id]
    bundle = json.loads((tmp_path / "bundle.json").read_text())
    (tmp_path / "bad.json").write_text(json.dumps(_tampered(bundle, "decision")))
    bad = run("verify", str(tmp_path / "bad.json"), "--hub-key", str(tmp_path / "hub.pem"))
    assert bad.returncode == 1 and not json.loads(bad.stdout)["valid"]
