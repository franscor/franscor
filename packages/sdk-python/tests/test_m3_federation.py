"""M3: hub federation — mutual allow-list, cross-hub discovery and delegation,
end-to-end encryption across hubs, revocation gossip."""

import asyncio

import pytest

import franscor
from franscor import errors as E
from franscor.capabilities import Capability, clear_registry
from franscor.evidence import read_log
from franscor.hub import Hub
from franscor.identity import Identity


@pytest.fixture(autouse=True)
def _clean():
    clear_registry()
    yield
    clear_registry()


async def until(predicate, timeout=5.0):
    for _ in range(int(timeout / 0.02)):
        if predicate():
            return True
        await asyncio.sleep(0.02)
    raise AssertionError("condition not reached")


async def federation(n=2, chain=False):
    """Start n hubs; each dials the previous one. All pairs allow each other
    unless `chain`, where only neighbours do (A-B-C)."""
    ids = [Identity.generate() for _ in range(n)]
    hubs = []
    for i, ident in enumerate(ids):
        allowed = [x.agent_id for j, x in enumerate(ids) if j != i and (not chain or abs(i - j) == 1)]
        peers = [hubs[i - 1].url] if i else []
        hubs.append(await Hub("127.0.0.1", 0, identity=ident, peers=peers, allowed_peers=allowed).start())
    for i in range(1, n):
        await until(lambda i=i: ids[i - 1].agent_id in hubs[i].links and ids[i].agent_id in hubs[i - 1].links)
    return hubs


async def make(hub, tmp_path, name, caps=(), **kw):
    kw.setdefault("load_plugins", False)
    kw.setdefault("reconnect", False)
    return await franscor.connect(name, hub_url=hub.url, home=tmp_path / name, tools=list(caps), **kw)


async def test_cross_hub_discovery_and_encrypted_delegation(tmp_path):
    a, b = await federation()
    a.tap, b.tap = [], []
    worker = await make(a, tmp_path, "fx", [Capability("fx.rate", lambda pair: {"rate": 1.0842, "pair": pair}, risk="R1")],
                        org="acme", visibility="public", accept_orgs=["acme", "globex"])
    hidden = await make(a, tmp_path, "internal", [Capability("fx.rate", lambda pair: {}, risk="R1")], org="acme")
    boss = await make(b, tmp_path, "boss", org="globex")
    try:
        await until(lambda: worker.agent_id in b.remote)
        found = await boss.discover("fx.rate")
        assert [c["agent_id"] for c in found] == [worker.agent_id]  # org-only agent not shared
        out = await boss.delegate("fx.rate", {"pair": "EUR/USD-SECRET"})
        assert out == {"rate": 1.0842, "pair": "EUR/USD-SECRET"}
        # Neither hub saw the payload.
        for hub in (a, b):
            assert "EUR/USD-SECRET" not in "\n".join(str(f) for f in hub.tap)
        record = read_log(worker.evidence.path)[-1]
        assert record["execution"]["requester"] == boss.agent_id
        assert record["execution"]["status"] == "executed"
        # The hidden agent cannot be reached across hubs either, even by ID.
        with pytest.raises(franscor.TaskError) as err:
            await boss.delegate("fx.rate", {"pair": "x"}, to=hidden.agent_id, timeout=3)
        assert err.value.code == E.OFFLINE
    finally:
        for agent in (boss, hidden, worker):
            await agent.close()
        await b.stop()
        await a.stop()


async def test_receiving_hub_enforces_accepts(tmp_path):
    a, b = await federation()
    worker = await make(a, tmp_path, "w", [Capability("x.run", lambda: {"ok": 1})],
                        org="acme", visibility="public")  # accepts acme only
    boss = await make(b, tmp_path, "boss", org="globex")
    try:
        await until(lambda: worker.agent_id in b.remote)
        with pytest.raises(franscor.TaskError) as err:
            await boss.delegate("x.run", {}, timeout=3)
        assert err.value.code == E.DENIED
    finally:
        await boss.close()
        await worker.close()
        await b.stop()
        await a.stop()


async def test_link_requires_mutual_allow_list(tmp_path):
    a = await Hub("127.0.0.1", 0, allowed_peers=[]).start()  # allows nobody
    b = await Hub("127.0.0.1", 0, peers=[a.url], allowed_peers=[a.identity.agent_id]).start()
    try:
        await asyncio.sleep(0.5)
        assert a.links == {} and b.links == {}
    finally:
        await b.stop()
        await a.stop()


async def test_dialer_refuses_unexpected_hub_key(tmp_path):
    a = await Hub("127.0.0.1", 0, allowed_peers=["fsp:" + "1" * 32]).start()
    b = await Hub("127.0.0.1", 0, peers=[a.url], allowed_peers=["fsp:" + "2" * 32]).start()
    try:
        await asyncio.sleep(0.5)
        assert b.links == {} and a.links == {}
    finally:
        await b.stop()
        await a.stop()


async def test_revocation_gossips_across_the_federation(tmp_path):
    a, b, c = await federation(3, chain=True)  # A-B-C: A and C are not linked
    assert c.identity.agent_id not in a.links
    victim = Identity.generate()
    agent = await franscor.connect("v", hub_url=a.url, home=tmp_path, identity=victim, visibility="public",
                                   load_plugins=False, reconnect=False)
    try:
        await until(lambda: victim.agent_id in b.remote)
        await agent.revoke_key("stolen laptop")
        await until(lambda: victim.agent_id in c.revoked)
        assert victim.agent_id in b.revoked and victim.agent_id not in b.remote
        # The stolen key cannot reconnect on any hub of the federation.
        for hub in (a, b, c):
            with pytest.raises(franscor.FSPError) as err:
                await franscor.connect("v", hub_url=hub.url, home=tmp_path, identity=victim,
                                       load_plugins=False, reconnect=False)
            assert err.value.code == E.REVOKED
    finally:
        for hub in (c, b, a):
            await hub.stop()


async def test_revocation_learned_from_peer_disconnects_local_session(tmp_path):
    a, b = await federation()
    victim = Identity.generate()
    on_a = await franscor.connect("v", hub_url=a.url, home=tmp_path / "a", identity=victim,
                                  load_plugins=False, reconnect=False)
    on_b = await franscor.connect("v", hub_url=b.url, home=tmp_path / "b", identity=victim,
                                  load_plugins=False, reconnect=False)
    try:
        await on_a.revoke_key("compromised")
        await until(lambda: on_b.status == "disconnected")
        assert victim.agent_id not in b.sessions
    finally:
        await on_b.close()
        await b.stop()
        await a.stop()
