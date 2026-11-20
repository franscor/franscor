"""Permits (FSP 0.2 §2): issuance from a peering file, offline verification,
enforcement before routing, revocation, and the attacks they must stop —
forged, foreign, tampered, re-bound, out-of-scope, too deep, too fast."""

import asyncio
import json
import os
import subprocess
import sys

import pytest

import franscor
from franscor import errors as E
from franscor.capabilities import Capability, clear_registry
from franscor.envelope import seal
from franscor.evidence import read_log
from franscor.hub import Hub
from franscor.identity import Identity
from franscor.passport import issue_passport
from franscor.permit import PermitOffice, issue_permit, load_peering, revoke_in_file, verify_permit

HUB = Identity.generate()          # receiving hub: issues permits
PARTNER = Identity.generate()      # partner hub: issues passports
AGENT = Identity.generate()
NOW = 1_000_000


def passport(**kw):
    kw.setdefault("now", NOW)
    kw.setdefault("ttl_ms", 3_600_000)
    return issue_passport(PARTNER, agent_id=AGENT.agent_id, org="globex", agent_public_key=AGENT.public_pem,
                          capabilities=[], **kw)


def permit(pp=None, **kw):
    kw.setdefault("now", NOW)
    kw.setdefault("capabilities", ["invoice.total", "fx.*"])
    kw.setdefault("scopes", ["invoices:read"])
    kw.setdefault("max_depth", 1)
    return issue_permit(HUB, pp or passport(), **kw)


TRUST = {HUB.agent_id: HUB.public_pem}


@pytest.fixture(autouse=True)
def _clean():
    clear_registry()
    yield
    clear_registry()


# -- offline verification -----------------------------------------------------------

def test_valid_permit_verifies_offline_and_covers_its_terms():
    pp = passport()
    p = permit(pp)
    assert p["peer_hub_id"] == PARTNER.agent_id and p["passport_id"] == pp["passport_id"]
    ok = verify_permit(p, trusted_hubs=TRUST, agent_id=AGENT.agent_id, passport=pp,
                       capability="fx.rate", scopes=["invoices:read"], depth=1, now=NOW + 1000)
    assert ok["permit_id"].startswith("pm_")


def test_permit_never_outlives_its_passport():
    pp = passport(ttl_ms=60_000)
    assert permit(pp, ttl_ms=3_600_000)["expires_at"] == pp["expires_at"]


@pytest.mark.parametrize("field, value", [
    ("capabilities", ["*"]),            # privilege escalation
    ("scopes", ["invoices:write"]),
    ("max_depth", 9),
    ("rate_per_min", 100_000),
    ("expires_at", 9_999_999_999),      # self-extended
    ("agent_id", Identity.generate().agent_id),
])
def test_tampered_permit_is_rejected(field, value):
    p = permit()
    p[field] = value
    with pytest.raises(E.FSPError) as err:
        verify_permit(p, trusted_hubs=TRUST, now=NOW + 1000)
    assert err.value.code == E.PERMIT_INVALID


def test_permit_forged_by_another_hub_is_rejected():
    forged = issue_permit(Identity.generate(), passport(), capabilities=["*"], now=NOW)
    with pytest.raises(E.FSPError) as err:
        verify_permit(forged, trusted_hubs=TRUST, now=NOW + 1000)
    assert err.value.code == E.PERMIT_INVALID


def test_permit_swapped_issuer_fields_are_rejected():
    forged = issue_permit(Identity.generate(), passport(), capabilities=["*"], now=NOW)
    forged["hub_id"] = HUB.agent_id   # claims the trusted hub, signed by another key
    with pytest.raises(E.FSPError) as err:
        verify_permit(forged, trusted_hubs=TRUST, now=NOW + 1000)
    assert err.value.code == E.PERMIT_INVALID


def test_permit_of_another_agent_or_passport_is_rejected():
    p = permit()
    with pytest.raises(E.FSPError) as err:
        verify_permit(p, trusted_hubs=TRUST, agent_id=Identity.generate().agent_id, now=NOW + 1000)
    assert err.value.code == E.PERMIT_INVALID
    other_passport = passport()   # same agent, renewed passport: the old permit is not bound to it
    with pytest.raises(E.FSPError) as err:
        verify_permit(p, trusted_hubs=TRUST, passport=other_passport, now=NOW + 1000)
    assert err.value.code == E.PERMIT_INVALID


def test_expired_revoked_and_future_permits():
    p = permit(ttl_ms=10_000)
    with pytest.raises(E.FSPError) as err:
        verify_permit(p, trusted_hubs=TRUST, now=NOW + 10_000)
    assert err.value.code == E.PERMIT_EXPIRED
    with pytest.raises(E.FSPError) as err:
        verify_permit(p, trusted_hubs=TRUST, revoked=[p["permit_id"]], now=NOW + 1000)
    assert err.value.code == E.PERMIT_REVOKED
    with pytest.raises(E.FSPError) as err:
        verify_permit(permit(now=NOW + 600_000), trusted_hubs=TRUST, now=NOW)
    assert err.value.code == E.PERMIT_INVALID


@pytest.mark.parametrize("kw", [
    {"capability": "payment.send"},
    {"capability": "fxrate"},                    # "fx.*" is a family, not a prefix of any string
    {"capability": "invoice.total", "scopes": ["invoices:write"]},
    {"capability": "invoice.total", "depth": 2},
    {"message": True},
])
def test_actions_outside_the_permit_are_denied(kw):
    with pytest.raises(E.FSPError) as err:
        verify_permit(permit(), trusted_hubs=TRUST, now=NOW + 1000, **kw)
    assert err.value.code == E.PERMIT_DENIED


def test_peering_file_is_validated():
    with pytest.raises(ValueError):
        load_peering({"type": "something-else"})
    with pytest.raises(ValueError):
        load_peering({"type": "peering", "peers": [{"hub_id": PARTNER.agent_id, "rules": [{"orgs": ["*"]}]}]})


def test_office_rate_limit_and_revocation_by_agent():
    clock = [NOW]
    office = PermitOffice(HUB, clock=lambda: clock[0])
    office.peers = {PARTNER.agent_id: {"name": "globex", "rules": [
        load_peering({"type": "peering", "peers": [{"hub_id": PARTNER.agent_id, "rules": [
            {"orgs": ["globex"], "capabilities": ["invoice.total"], "rate_per_min": 2}]}]})
        ["peers"][PARTNER.agent_id]["rules"][0]]}}
    pp = passport()
    p = office.permit_for(PARTNER.agent_id, pp)
    assert office.permit_for(PARTNER.agent_id, pp) is p          # cached per passport
    office.check(p, capability="invoice.total", scopes=[], depth=0)
    office.check(p, capability="invoice.total", scopes=[], depth=0)
    with pytest.raises(E.FSPError) as err:
        office.check(p, capability="invoice.total", scopes=[], depth=0)
    assert err.value.code == E.PERMIT_DENIED
    clock[0] += 30_000                                           # half a minute refills one
    office.check(p, capability="invoice.total", scopes=[], depth=0)
    office.revoke(p["permit_id"], reason="contract ended")
    with pytest.raises(E.FSPError) as err:                      # a new passport does not help
        office.permit_for(PARTNER.agent_id, passport())
    assert err.value.code == E.PERMIT_REVOKED
    with pytest.raises(E.FSPError) as err:                      # unknown partner hub
        office.permit_for(Identity.generate().agent_id, pp)
    assert err.value.code == E.PERMIT_DENIED


# -- enforcement across a federation link --------------------------------------------

async def until(predicate, timeout=5.0):
    for _ in range(int(timeout / 0.02)):
        if predicate():
            return True
        await asyncio.sleep(0.02)
    raise AssertionError("condition not reached")


def peering_file(path, partner_id, **rule):
    rule = {"orgs": ["globex"], "agents": ["*"], "capabilities": ["invoice.total", "fx.*"],
            "scopes": ["invoices:read"], "rate_per_min": 60, "max_depth": 0, "ttl": "1h", **rule}
    path.write_text(json.dumps({"fsp": "0.2", "type": "peering",
                                "peers": [{"hub_id": partner_id, "name": "globex", "rules": [rule]}]}))
    return path


async def pair(tmp_path, peering=None, **rule):
    """Hub B (acme, receiving, with a peering file) federated with hub A (globex)."""
    a_id, b_id = Identity.generate(), Identity.generate()
    path = peering_file(tmp_path / "peering.json", a_id.agent_id, **rule) if peering is None else peering
    b = await Hub("127.0.0.1", 0, identity=b_id, allowed_peers=[a_id.agent_id],
                  peering=path or None).start()
    a = await Hub("127.0.0.1", 0, identity=a_id, allowed_peers=[b_id.agent_id], peers=[b.url]).start()
    await until(lambda: a_id.agent_id in b.links and b_id.agent_id in a.links)
    return a, b, path


async def make(hub, tmp_path, name, caps=(), **kw):
    kw.setdefault("load_plugins", False)
    kw.setdefault("reconnect", False)
    return await franscor.connect(name, hub_url=hub.url, home=tmp_path / name, tools=list(caps), **kw)


def invoices():
    return [Capability("invoice.total", lambda lines: {"total": sum(lines)}, risk="R1"),
            Capability("payment.send", lambda amount: {"sent": amount}, risk="R1")]


async def test_permit_allows_only_what_the_peering_file_grants(tmp_path):
    a, b, _ = await pair(tmp_path, rate_per_min=3)
    worker = await make(b, tmp_path, "worker", invoices(), org="acme", visibility="public",
                        accept_orgs=["acme", "globex", "initech"])
    boss = await make(a, tmp_path, "boss", org="globex")
    stranger = await make(a, tmp_path, "stranger", org="initech")
    no_passport = await make(a, tmp_path, "nopass", org="globex", passport="off")
    try:
        await until(lambda: worker.agent_id in a.remote)
        assert await boss.delegate("invoice.total", {"lines": [1, 2]}, to=worker.agent_id,
                                   scopes=["invoices:read"]) == {"total": 3}
        record = read_log(worker.evidence.path)[-1]
        assert record["execution"]["permit_id"].startswith("pm_")
        assert record["execution"]["passport_id"] == boss.passport["passport_id"]

        async def refused(agent, cap, **kw):
            with pytest.raises(franscor.TaskError) as err:
                await agent.delegate(cap, {"amount": 1} if cap == "payment.send" else {"lines": [1]},
                                     to=worker.agent_id, timeout=3, retries=0, **kw)
            return err.value.code

        assert await refused(boss, "payment.send") == E.DENIED                       # not granted
        assert await refused(boss, "invoice.total", scopes=["invoices:write"]) == E.DENIED
        assert await refused(stranger, "invoice.total") == E.DENIED                  # org not in the rules
        assert await refused(no_passport, "invoice.total") == E.DENIED               # no passport
        await boss.delegate("invoice.total", {"lines": [1]}, to=worker.agent_id)
        await boss.delegate("invoice.total", {"lines": [1]}, to=worker.agent_id)
        assert await refused(boss, "invoice.total") == E.DENIED                      # 3/min used
        # Nothing refused ever reached the worker.
        executed = [r for r in read_log(worker.evidence.path)]
        assert len(executed) == 3 and all(r["execution"]["status"] == "executed" for r in executed)
        snap = b.snapshot()
        assert snap["permits"]["enforcing"] and len(snap["permits"]["active"]) == 1
        assert snap["traffic"]["inbound"]["denied"] == 5
    finally:
        for agent in (no_passport, stranger, boss, worker):
            await agent.close()
        await a.stop()
        await b.stop()


async def test_messages_need_a_permit_that_allows_them(tmp_path):
    a, b, _ = await pair(tmp_path)
    worker = await make(b, tmp_path, "worker", invoices(), org="acme", visibility="public",
                        accept_orgs=["acme", "globex"])
    got = []
    worker.on_message("news")(lambda data, sender: got.append(data))
    boss = await make(a, tmp_path, "boss", org="globex")
    try:
        await until(lambda: worker.agent_id in a.remote)
        await boss.send(worker.agent_id, "news", {"x": 1})
        await asyncio.sleep(0.5)
        assert got == [] and b.traffic["inbound"]["denied"] == 1
    finally:
        for agent in (boss, worker):
            await agent.close()
        await a.stop()
        await b.stop()


async def test_delegation_depth_is_bounded(tmp_path):
    a, b, _ = await pair(tmp_path, max_depth=0)
    worker = await make(b, tmp_path, "worker", invoices(), org="acme", visibility="public",
                        accept_orgs=["acme", "globex"])
    holder = {}

    async def relay(lines):   # a globex agent that forwards a task it received
        return await holder["boss"].delegate("invoice.total", {"lines": lines}, to=worker.agent_id,
                                             timeout=3, retries=0)

    boss = await make(a, tmp_path, "boss", [Capability("relay", relay, risk="R1")], org="globex")
    holder["boss"] = boss
    front = await make(a, tmp_path, "front", org="globex")
    try:
        await until(lambda: worker.agent_id in a.remote)
        assert await boss.delegate("invoice.total", {"lines": [5]}, to=worker.agent_id) == {"total": 5}
        with pytest.raises(franscor.TaskError) as err:     # front -> boss -> worker: depth 1 > 0
            await front.delegate("relay", {"lines": [5]}, to=boss.agent_id, timeout=5, retries=0)
        assert err.value.code == E.HANDLER_FAILED          # boss's handler got the refusal
    finally:
        for agent in (front, boss, worker):
            await agent.close()
        await a.stop()
        await b.stop()


async def test_revocation_applies_immediately_and_from_the_file(tmp_path):
    a, b, path = await pair(tmp_path)
    worker = await make(b, tmp_path, "worker", invoices(), org="acme", visibility="public",
                        accept_orgs=["acme", "globex"])
    boss = await make(a, tmp_path, "boss", org="globex")
    other = await make(a, tmp_path, "other", org="globex")
    try:
        await until(lambda: worker.agent_id in a.remote)
        await boss.delegate("invoice.total", {"lines": [1]}, to=worker.agent_id)
        await other.delegate("invoice.total", {"lines": [1]}, to=worker.agent_id)
        pid = next(p["permit_id"] for p in b.permits.issued.values() if p["agent_id"] == boss.agent_id)
        await b.revoke_permit(pid, reason="test")
        with pytest.raises(franscor.TaskError):
            await boss.delegate("invoice.total", {"lines": [1]}, to=worker.agent_id, timeout=3, retries=0)
        assert pid in json.loads(path.read_text())["revoked"][0]["permit_id"]
        # Offline revocation by permit ID alone, picked up by the running hub.
        other_pid = next(p["permit_id"] for p in b.permits.issued.values() if p["agent_id"] == other.agent_id)
        revoke_in_file(path, other_pid, reason="offline")
        await asyncio.sleep(1.5)
        with pytest.raises(franscor.TaskError):
            await other.delegate("invoice.total", {"lines": [1]}, to=worker.agent_id, timeout=3, retries=0)
        entry = [r for r in json.loads(path.read_text())["revoked"] if r["permit_id"] == other_pid][0]
        assert entry["agent_id"] == other.agent_id      # completed by the hub from its records
    finally:
        for agent in (other, boss, worker):
            await agent.close()
        await a.stop()
        await b.stop()


async def test_without_peering_file_federation_keeps_fsp01_behaviour(tmp_path):
    a, b, _ = await pair(tmp_path, peering=False)
    worker = await make(b, tmp_path, "worker", invoices(), org="acme", visibility="public",
                        accept_orgs=["acme", "globex"])
    boss = await make(a, tmp_path, "boss", org="globex")
    try:
        await until(lambda: worker.agent_id in a.remote)
        assert await boss.delegate("payment.send", {"amount": 4}, to=worker.agent_id) == {"sent": 4}
        assert "permit_id" not in read_log(worker.evidence.path)[-1]["execution"]
    finally:
        for agent in (boss, worker):
            await agent.close()
        await a.stop()
        await b.stop()


async def test_receiver_checks_the_permit_itself(tmp_path):
    """The executing agent does not trust the hub blindly: forged, re-bound or
    insufficient permits are refused, and `permit="require"` refuses partners without one."""
    a, b, _ = await pair(tmp_path, peering=False)
    worker = await make(b, tmp_path, "worker", invoices(), org="acme", visibility="public",
                        accept_orgs=["acme", "globex"], permit="require")
    mallory = await make(a, tmp_path, "mallory", org="globex")
    try:
        await until(lambda: worker.agent_id in a.remote and a.identity.agent_id in worker.trusted_issuers)
        # require: a partner agent without a permit is refused
        with pytest.raises(franscor.TaskError) as err:
            await mallory.delegate("invoice.total", {"lines": [1]}, to=worker.agent_id, timeout=3, retries=0)
        assert err.value.code == E.PERMIT_INVALID
        assert read_log(worker.evidence.path)[-1]["authorization"]["rule"] == "permit-required"

        def request(task_id, capability="invoice.total"):
            return seal(mallory._identity, "task.request", {
                "task_id": task_id, "capability": capability, "input": {"lines": [1]},
                "deadline_ms": 3000, "passport": mallory.passport}, to=worker.agent_id)

        good = issue_permit(b.identity, mallory.passport, capabilities=["invoice.total"])
        cases = [
            (issue_permit(Identity.generate(), mallory.passport, capabilities=["*"]), E.PERMIT_INVALID),
            (issue_permit(b.identity, mallory.passport, capabilities=["fx.rate"]), E.PERMIT_DENIED),
            (issue_permit(b.identity, {**mallory.passport, "passport_id": "pp_" + "0" * 32},
                          capabilities=["*"]), E.PERMIT_INVALID),
        ]
        for i, (forged, code) in enumerate(cases):
            result = await worker._serve_task_inner(request(f"t{i}"), mallory.card, forged)
            assert result["status"] == "rejected" and result["error"]["code"] == code, (i, result)
        result = await worker._serve_task_inner(request("ok"), mallory.card, good)
        assert result["status"] == "completed"
        assert read_log(worker.evidence.path)[-1]["execution"]["permit_id"] == good["permit_id"]
    finally:
        for agent in (mallory, worker):
            await agent.close()
        await a.stop()
        await b.stop()


def test_cli_show_verify_and_revoke(tmp_path):
    pp = passport(now=None)
    p = permit(pp, now=None)
    (tmp_path / "permit.json").write_text(json.dumps(p))
    (tmp_path / "hub.pem").write_text(HUB.public_pem)
    path = peering_file(tmp_path / "peering.json", PARTNER.agent_id)
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}

    def run(*args):
        return subprocess.run([sys.executable, "-m", "franscor.cli", "permit", *args],
                              capture_output=True, text=True, env=env)

    shown = run("show", str(tmp_path / "permit.json"))
    assert shown.returncode == 0 and p["permit_id"] in shown.stdout
    assert "invoice.total" in run("show", str(path)).stdout
    ok = run("verify", str(tmp_path / "permit.json"), "--hub-key", str(tmp_path / "hub.pem"),
             "--capability", "invoice.total")
    assert ok.returncode == 0 and json.loads(ok.stdout)["valid"]
    bad = run("verify", str(tmp_path / "permit.json"), "--hub-key", str(tmp_path / "hub.pem"),
              "--capability", "payment.send")
    assert bad.returncode == 1 and json.loads(bad.stdout)["code"] == E.PERMIT_DENIED
    assert run("revoke", str(tmp_path / "permit.json"), "--peering", str(path)).returncode == 0
    entry = json.loads(path.read_text())["revoked"][0]
    assert entry["permit_id"] == p["permit_id"] and entry["agent_id"] == AGENT.agent_id


def test_peering_file_matches_its_schema(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    from pathlib import Path
    schemas = Path(__file__).resolve().parents[3] / "protocol" / "schemas"
    path = peering_file(tmp_path / "peering.json", PARTNER.agent_id)
    revoke_in_file(path, agent_id=AGENT.agent_id, peer_hub_id=PARTNER.agent_id, reason="schema")
    jsonschema.validate(json.loads(path.read_text()), json.loads((schemas / "peering.json").read_text("utf-8")))
    jsonschema.validate(permit(), json.loads((schemas / "permit.json").read_text("utf-8")))
