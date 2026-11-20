"""Operator channel: the console observes a hub read-only, with an allow-listed key."""

import json

import pytest

import franscor
from franscor import errors as E
from franscor.capabilities import Capability, clear_registry
from franscor.envelope import seal, verify
from franscor.hub import Hub
from franscor.identity import Identity


@pytest.fixture(autouse=True)
def _clean():
    clear_registry()
    yield
    clear_registry()


async def operator_session(url, ident):
    from websockets.asyncio.client import connect

    ws = await connect(url)
    challenge = json.loads(await ws.recv())
    hub_pem = challenge["body"]["hub_public_key"]
    verify(challenge, hub_pem)
    await ws.send(json.dumps(seal(ident, "operator.hello",
                                  {"nonce": challenge["body"]["nonce"], "public_key": ident.public_pem})))
    reply = json.loads(await ws.recv())
    verify(reply, hub_pem)
    return ws, reply, hub_pem


async def test_operator_gets_a_signed_metadata_snapshot(tmp_path):
    op = Identity.generate()
    hub = await Hub("127.0.0.1", 0, operators=[op.agent_id]).start()
    worker = await franscor.connect("w", hub_url=hub.url, home=tmp_path / "w", load_plugins=False, reconnect=False,
                                    tools=[Capability("x.run", lambda secret: {"ok": 1}, risk="R2")])
    boss = await franscor.connect("b", hub_url=hub.url, home=tmp_path / "b", load_plugins=False, reconnect=False)
    try:
        await boss.delegate("x.run", {"secret": "NEVER-IN-SNAPSHOT"})
        ws, welcome, hub_pem = await operator_session(hub.url, op)
        assert welcome["type"] == "welcome" and welcome["body"]["role"] == "operator"
        await ws.send(json.dumps(seal(op, "hub.observe", {})))
        snap = json.loads(await ws.recv())
        verify(snap, hub_pem)
        body = snap["body"]
        assert snap["type"] == "hub.snapshot" and body["hub_id"] == hub.identity.agent_id
        assert {a["name"] for a in body["agents"]} == {"w", "b"}
        w = next(a for a in body["agents"] if a["name"] == "w")
        assert w["capabilities"] == [{"name": "x.run", "risk": "R2"}] and w["passport"]["passport_id"].startswith("pp_")
        assert body["traffic"]["routed"]["delivered"] >= 2
        text = json.dumps(snap)
        assert "NEVER-IN-SNAPSHOT" not in text and "PRIVATE" not in text
        await ws.close()
    finally:
        await boss.close()
        await worker.close()
        await hub.stop()


async def test_unknown_or_forged_operator_is_refused(tmp_path):
    allowed, stranger = Identity.generate(), Identity.generate()
    hub = await Hub("127.0.0.1", 0, operators=[allowed.agent_id]).start()
    try:
        ws, reply, _ = await operator_session(hub.url, stranger)
        assert reply["type"] == "error" and reply["body"]["code"] == E.DENIED
        await ws.close()

        # Claiming the allowed key without holding it: the signature does not verify.
        from websockets.asyncio.client import connect

        ws = await connect(hub.url)
        challenge = json.loads(await ws.recv())
        forged = seal(stranger, "operator.hello", {"nonce": challenge["body"]["nonce"],
                                                  "public_key": allowed.public_pem})
        forged["from"] = allowed.agent_id
        await ws.send(json.dumps(forged))
        reply = json.loads(await ws.recv())
        assert reply["type"] == "error"
        await ws.close()
    finally:
        await hub.stop()


async def test_no_operators_by_default(tmp_path):
    hub = await Hub("127.0.0.1", 0).start()
    try:
        ws, reply, _ = await operator_session(hub.url, Identity.generate())
        assert reply["type"] == "error"
        await ws.close()
    finally:
        await hub.stop()
