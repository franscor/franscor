"""Passports (FSP 0.2): issuance, offline verification, revocation, and the
attacks they must stop — forged, foreign, expired, revoked, replayed, tampered."""

import asyncio
import copy
import json
import os
import subprocess
import sys

import pytest

import franscor
from franscor import errors as E
from franscor.capabilities import Capability, clear_registry
from franscor.evidence import read_log
from franscor.hub import Hub
from franscor.identity import Identity
from franscor.passport import (PassportAuthority, crl_revokes, issue_passport, make_crl,
                               verify_crl, verify_passport)

HUB = Identity.generate()
OTHER_HUB = Identity.generate()
AGENT = Identity.generate()


def passport(**kw):
    kw.setdefault("now", 1_000_000)
    return issue_passport(HUB, agent_id=AGENT.agent_id, org="acme", agent_public_key=AGENT.public_pem,
                          capabilities=["math.add"], ttl_ms=60_000, **kw)


TRUST = {HUB.agent_id: HUB.public_pem}


# -- offline verification ---------------------------------------------------------

def test_valid_passport_verifies_offline_with_the_hub_key_only():
    p = passport()
    assert verify_passport(p, trusted_hubs=TRUST, now=1_010_000)["agent_id"] == AGENT.agent_id


@pytest.mark.parametrize("field, value", [
    ("capabilities", ["math.add", "db.drop"]),   # privilege escalation
    ("org", "evil-corp"),                         # org spoofing
    ("expires_at", 9_999_999_999),                # self-extended
])
def test_tampered_passport_is_rejected(field, value):
    p = passport()
    p[field] = value
    with pytest.raises(E.FSPError) as err:
        verify_passport(p, trusted_hubs=TRUST, now=1_010_000)
    assert err.value.code == E.PASSPORT_INVALID


def test_passport_forged_by_another_hub_is_rejected():
    forged = issue_passport(OTHER_HUB, agent_id=AGENT.agent_id, org="acme",
                            agent_public_key=AGENT.public_pem, capabilities=[], now=1_000_000)
    with pytest.raises(E.FSPError) as err:
        verify_passport(forged, trusted_hubs=TRUST, now=1_010_000)
    assert err.value.code == E.PASSPORT_INVALID
    # Swapping in the trusted hub's identity without its key breaks the signature.
    forged.update(hub_id=HUB.agent_id, hub_public_key=HUB.public_pem)
    with pytest.raises(E.FSPError):
        verify_passport(forged, trusted_hubs=TRUST, now=1_010_000)


def test_expired_and_future_passports():
    p = passport()
    with pytest.raises(E.FSPError) as err:
        verify_passport(p, trusted_hubs=TRUST, now=1_060_000)
    assert err.value.code == E.PASSPORT_EXPIRED
    with pytest.raises(E.FSPError) as err:
        verify_passport(p, trusted_hubs=TRUST, now=500_000)
    assert err.value.code == E.PASSPORT_INVALID


def test_revoked_passport_and_ban():
    p = passport()
    crl = make_crl(HUB, [{"passport_id": p["passport_id"], "agent_id": AGENT.agent_id,
                          "revoked_at": 1_005_000, "reason": "stolen", "ban": True}], serial=1)
    verify_crl(crl, HUB.public_pem)
    with pytest.raises(E.FSPError) as err:
        verify_passport(p, trusted_hubs=TRUST, crls={HUB.agent_id: crl}, now=1_010_000)
    assert err.value.code == E.PASSPORT_REVOKED
    older = passport(passport_id="pp_" + "1" * 32)  # another passport of the banned agent
    assert crl_revokes(crl, older)


def test_forged_crl_is_rejected():
    crl = make_crl(HUB, [], serial=3)
    crl["revoked"].append({"passport_id": "pp_" + "2" * 32, "agent_id": "", "revoked_at": 1, "reason": "x", "ban": False})
    with pytest.raises(E.FSPError):
        verify_crl(crl, HUB.public_pem)
    with pytest.raises(E.FSPError):
        verify_crl(make_crl(OTHER_HUB, [], serial=4), HUB.public_pem)


def test_authority_crl_file_roundtrip(tmp_path):
    path = tmp_path / "crl.json"
    office = PassportAuthority(HUB, crl_path=path)
    card = {"agent_id": AGENT.agent_id, "org": "acme", "public_key": AGENT.public_pem, "capabilities": []}
    p = office.issue(card)
    office.revoke(p["passport_id"], reason="test")
    assert office.issue(card) is None  # banned: no new passport
    reopened = PassportAuthority(HUB, crl_path=path)
    assert reopened.crl["serial"] == 1 and crl_revokes(reopened.crl, p)


# -- over the network ------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean():
    clear_registry()
    yield
    clear_registry()


@pytest.fixture
async def hub(tmp_path):
    h = await Hub("127.0.0.1", 0, crl=tmp_path / "hub-crl.json").start()
    yield h
    await h.stop()


async def make(hub, tmp_path, name, caps=(), **kw):
    kw.setdefault("load_plugins", False)
    kw.setdefault("reconnect", False)
    return await franscor.connect(name, hub_url=hub.url, home=tmp_path / name, tools=list(caps), **kw)


async def test_hub_issues_passports_and_receivers_record_them(hub, tmp_path):
    worker = await make(hub, tmp_path, "w", [Capability("x.run", lambda: {"ok": 1})], passport="require")
    boss = await make(hub, tmp_path, "b")
    try:
        assert boss.passport["agent_id"] == boss.agent_id
        assert boss.passport["hub_id"] == hub.identity.agent_id
        assert worker.trusted_issuers == {hub.identity.agent_id: hub.identity.public_pem}
        assert await boss.delegate("x.run", {}) == {"ok": 1}
        record = read_log(worker.evidence.path)[-1]
        assert record["execution"]["passport_id"] == boss.passport["passport_id"]
    finally:
        await boss.close()
        await worker.close()


async def test_require_mode_refuses_agents_without_passport(hub, tmp_path):
    worker = await make(hub, tmp_path, "w", [Capability("x.run", lambda: {"ok": 1})], passport="require")
    legacy = await make(hub, tmp_path, "legacy", passport="off")  # behaves like an FSP 0.1 agent
    tolerant = await make(hub, tmp_path, "t", [Capability("x.run", lambda: {"ok": 2})])
    try:
        with pytest.raises(franscor.TaskError) as err:
            await legacy.delegate("x.run", {}, to=worker.agent_id)
        assert err.value.code == E.PASSPORT_INVALID
        # Backward compatible by default: "verify" accepts a sender without passport.
        assert await legacy.delegate("x.run", {}, to=tolerant.agent_id) == {"ok": 2}
    finally:
        for a in (tolerant, legacy, worker):
            await a.close()


async def test_presented_passport_attacks_are_rejected(hub, tmp_path):
    worker = await make(hub, tmp_path, "w", [Capability("x.run", lambda: {"ok": 1})], passport="require")
    boss = await make(hub, tmp_path, "b")
    victim = await make(hub, tmp_path, "v")
    real = boss.passport
    attacks = {
        "forged by an unknown hub": (issue_passport(OTHER_HUB, agent_id=boss.agent_id, org="local",
                                                    agent_public_key=boss.identity["public_key"],
                                                    capabilities=[]), E.PASSPORT_INVALID),
        "another agent's passport (replay)": (victim.passport, E.PASSPORT_INVALID),
        "capabilities tampered": ({**real, "capabilities": ["admin.everything"]}, E.PASSPORT_INVALID),
        "expired": (issue_passport(hub.identity, agent_id=boss.agent_id, org="local",
                                   agent_public_key=boss.identity["public_key"], capabilities=[],
                                   ttl_ms=1, now=1_000), E.PASSPORT_EXPIRED),
    }
    try:
        for label, (presented, code) in attacks.items():
            # A malicious client sends what it wants: bypass the SDK's own renewal.
            async def present(value=presented):
                return value
            boss._current_passport = present
            with pytest.raises(franscor.TaskError) as err:
                await boss.delegate("x.run", {}, to=worker.agent_id, retries=0)
            assert err.value.code == code, label
        rules = [r["authorization"]["rule"] for r in read_log(worker.evidence.path)]
        assert rules == ["passport-invalid", "passport-invalid", "passport-invalid", "passport-expired"]
    finally:
        for a in (victim, boss, worker):
            await a.close()


async def test_live_revocation_reaches_receivers_and_blocks_reconnection(hub, tmp_path):
    worker = await make(hub, tmp_path, "w", [Capability("x.run", lambda: {"ok": 1})])
    boss = await make(hub, tmp_path, "b")
    try:
        assert await boss.delegate("x.run", {}) == {"ok": 1}
        await hub.revoke_passport(boss.passport["passport_id"], reason="compromised")
        for _ in range(100):
            if worker._crls.get(hub.identity.agent_id, {}).get("serial") == 1:
                break
            await asyncio.sleep(0.02)
        with pytest.raises(franscor.TaskError) as err:
            await boss.delegate("x.run", {}, retries=0)
        assert err.value.code == E.PASSPORT_REVOKED
        await boss.close()
        with pytest.raises(franscor.FSPError) as err:  # banned: no new passport by reconnecting
            await make(hub, tmp_path, "b")
        assert err.value.code == E.PASSPORT_REVOKED
    finally:
        await boss.close()
        await worker.close()


async def test_short_lived_passport_is_renewed_before_use(tmp_path):
    h = await Hub("127.0.0.1", 0, passport_ttl_ms=6_000).start()
    worker = await make(h, tmp_path, "w", [Capability("x.run", lambda: {"ok": 1})], passport="require")
    boss = await make(h, tmp_path, "b")
    try:
        first = boss.passport["passport_id"]
        await asyncio.sleep(1.2)  # inside the renewal margin (min 5 s)
        assert await boss.delegate("x.run", {}) == {"ok": 1}
        assert boss.passport["passport_id"] != first
    finally:
        await boss.close()
        await worker.close()
        await h.stop()


async def test_passports_and_crls_cross_federated_hubs(tmp_path):
    a_id, b_id = Identity.generate(), Identity.generate()
    a = await Hub("127.0.0.1", 0, identity=a_id, allowed_peers=[b_id.agent_id]).start()
    b = await Hub("127.0.0.1", 0, identity=b_id, peers=[a.url], allowed_peers=[a_id.agent_id]).start()
    try:
        for _ in range(250):
            if b_id.agent_id in a.links and a_id.agent_id in b.links:
                break
            await asyncio.sleep(0.02)
        worker = await make(a, tmp_path, "w", [Capability("x.run", lambda: {"ok": 1})], org="acme",
                            visibility="public", accept_orgs=["acme", "globex"], passport="require")
        boss = await make(b, tmp_path, "b", org="globex")
        for _ in range(250):
            if worker.agent_id in b.remote and b_id.agent_id in worker.trusted_issuers:
                break
            await asyncio.sleep(0.02)
        assert await boss.delegate("x.run", {}) == {"ok": 1}  # B-issued passport trusted on A
        await b.revoke_passport(boss.passport["passport_id"], reason="left the company")
        for _ in range(250):
            if worker._crls.get(b_id.agent_id, {}).get("serial") == 1:
                break
            await asyncio.sleep(0.02)
        with pytest.raises(franscor.TaskError) as err:
            await boss.delegate("x.run", {}, retries=0)
        assert err.value.code == E.PASSPORT_REVOKED
        await boss.close()
        await worker.close()
    finally:
        await b.stop()
        await a.stop()


# -- CLI ---------------------------------------------------------------------------

def run(*args, env):
    return subprocess.run([sys.executable, "-m", "franscor.cli", *args], capture_output=True,
                          text=True, env=env, timeout=60)


def test_cli_issue_show_verify_revoke(tmp_path):
    env = {**os.environ, "FRANSCOR_HOME": str(tmp_path / "home")}
    run("identity", "hub-eu", env=env)
    hub_pem = json.loads(run("identity", "hub-eu", env=env).stdout)["public_key"]
    (tmp_path / "hub.pem").write_text(hub_pem, "utf-8")
    out = tmp_path / "pp.json"
    r = run("passport", "issue", "--hub", "hub-eu", "--agent", "worker", "--org", "acme",
            "--capability", "math.add", "--ttl", "1h", "--out", str(out), env=env)
    assert r.returncode == 0, r.stderr
    shown = run("passport", "show", str(out), env=env).stdout
    assert "acme" in shown and "math.add" in shown
    crl = tmp_path / "crl.json"
    ok = run("passport", "verify", str(out), "--hub-key", str(tmp_path / "hub.pem"), env=env)
    assert ok.returncode == 0 and json.loads(ok.stdout)["valid"]
    assert run("passport", "revoke", str(out), "--hub", "hub-eu", "--crl", str(crl), env=env).returncode == 0
    bad = run("passport", "verify", str(out), "--hub-key", str(tmp_path / "hub.pem"), "--crl", str(crl), env=env)
    assert bad.returncode == 1 and json.loads(bad.stdout)["code"] == E.PASSPORT_REVOKED
    assert "ban" in run("passport", "show", str(crl), env=env).stdout
    refused = run("passport", "issue", "--hub", "hub-eu", "--agent", "worker", "--org", "acme",
                  "--crl", str(crl), env=env)
    assert refused.returncode == 1
    # A passport edited by hand fails offline verification.
    doc = json.loads(out.read_text("utf-8"))
    doc["capabilities"].append("db.drop")
    out.write_text(json.dumps(doc), "utf-8")
    assert run("passport", "verify", str(out), "--hub-key", str(tmp_path / "hub.pem"), env=env).returncode == 1


async def test_running_hub_picks_up_cli_revocation(tmp_path):
    hub_ident = Identity.load_or_create("hub", tmp_path / "home")
    crl_path = tmp_path / "crl.json"
    h = await Hub("127.0.0.1", 0, identity=hub_ident, crl=crl_path).start()
    worker = await make(h, tmp_path, "w", [Capability("x.run", lambda: {"ok": 1})])
    boss = await make(h, tmp_path, "b")
    try:
        (tmp_path / "pp.json").write_text(json.dumps(boss.passport), "utf-8")
        env = {**os.environ, "FRANSCOR_HOME": str(tmp_path / "home")}
        r = await asyncio.to_thread(run, "passport", "revoke", str(tmp_path / "pp.json"), "--hub", "hub",
                                    "--crl", str(crl_path), env=env)
        assert r.returncode == 0, r.stderr
        for _ in range(150):
            if worker._crls.get(hub_ident.agent_id, {}).get("serial") == 1:
                break
            await asyncio.sleep(0.05)
        with pytest.raises(franscor.TaskError) as err:
            await boss.delegate("x.run", {}, retries=0)
        assert err.value.code == E.PASSPORT_REVOKED
    finally:
        await boss.close()
        await worker.close()
        await h.stop()


def test_trusted_key_with_windows_line_endings_still_matches():
    """Regression: a PEM file saved with CRLF is the same key, not an untrusted hub."""
    crlf = HUB.public_pem.replace("\n", "\r\n")
    assert verify_passport(passport(), trusted_hubs={HUB.agent_id: crlf}, now=1_010_000)
