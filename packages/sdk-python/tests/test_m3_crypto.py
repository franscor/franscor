"""M3: end-to-end payload encryption and signed cards."""

import asyncio
import copy

import pytest

import franscor
from franscor import errors as E
from franscor import sealing
from franscor.canonical import canonical_hash
from franscor.capabilities import Capability, clear_registry
from franscor.evidence import read_log
from franscor.hub import Hub
from franscor.identity import Identity


@pytest.fixture
async def hub():
    h = await Hub("127.0.0.1", 0).start()
    h.tap = []
    yield h
    await h.stop()


@pytest.fixture(autouse=True)
def _clean():
    clear_registry()
    yield
    clear_registry()


async def make(hub, tmp_path, name, caps=(), **kw):
    kw.setdefault("load_plugins", False)
    kw.setdefault("reconnect", False)
    return await franscor.connect(name, hub_url=hub.url, home=tmp_path / name, tools=list(caps), **kw)


def test_seal_open_and_binding():
    alice, bob, eve = Identity.generate(), Identity.generate(), Identity.generate()
    aad = sealing.aad("task.request", alice.agent_id, bob.agent_id, "t1")
    box = sealing.seal({"iban": "FR76", "amount": 12.5}, sealing.enc_public_b64(bob), aad)
    assert sealing.open_sealed(box, bob, aad) == {"iban": "FR76", "amount": 12.5}
    with pytest.raises(E.FSPError):  # wrong recipient
        sealing.open_sealed(box, eve, aad)
    with pytest.raises(E.FSPError):  # replayed into another task
        sealing.open_sealed(box, bob, sealing.aad("task.request", alice.agent_id, bob.agent_id, "t2"))
    tampered = dict(box, ct=box["ct"][:-2] + ("A" if box["ct"][-2] != "A" else "B") + box["ct"][-1])
    with pytest.raises(E.FSPError):
        sealing.open_sealed(tampered, bob, aad)


def test_card_signature_protects_the_encryption_key():
    me, attacker = Identity.generate(), Identity.generate()
    card = sealing.sign_card({"agent_id": me.agent_id, "public_key": me.public_pem,
                              "enc_key": sealing.enc_public_b64(me), "name": "me"}, me)
    assert sealing.enc_key_of(card) == sealing.enc_public_b64(me)
    swapped = dict(card, enc_key=sealing.enc_public_b64(attacker))
    assert not sealing.card_verified(swapped) and sealing.enc_key_of(swapped) is None
    resigned = sealing.sign_card(swapped, attacker)  # signed, but by a key that is not the agent's
    assert not sealing.card_verified(resigned)


async def test_hub_never_sees_inputs_or_outputs(hub, tmp_path):
    seen = []

    def vault(account: str) -> dict:
        seen.append(account)
        return {"balance": "TOP-SECRET-BALANCE"}

    worker = await make(hub, tmp_path, "vault", [Capability("vault.read", vault, risk="R2")])
    boss = await make(hub, tmp_path, "boss")
    received = []
    boss.on_message("note")(lambda data, sender: received.append(data))
    try:
        out = await boss.delegate("vault.read", {"account": "ACCOUNT-4242"})
        assert out == {"balance": "TOP-SECRET-BALANCE"} and seen == ["ACCOUNT-4242"]
        await worker.send(boss.agent_id, "note", {"memo": "SECRET-MEMO"})
        for _ in range(50):
            if received:
                break
            await asyncio.sleep(0.02)
        assert received == [{"memo": "SECRET-MEMO"}]
        wire = "\n".join(str(f) for f in hub.tap)
        for secret in ("ACCOUNT-4242", "TOP-SECRET-BALANCE", "SECRET-MEMO"):
            assert secret not in wire
        assert '"sealed"' in wire
        # Evidence hashes the plaintext input, so it stays verifiable by whoever holds it.
        rec = read_log(worker.evidence.path)[-1]
        assert rec["action"]["payload_hash"] == canonical_hash({"account": "ACCOUNT-4242"})
    finally:
        await boss.close()
        await worker.close()


async def test_required_encryption_refuses_plaintext(hub, tmp_path):
    worker = await make(hub, tmp_path, "w", [Capability("x.run", lambda: {"ok": 1})], encryption="required")
    legacy = await make(hub, tmp_path, "legacy", encryption="off")
    modern = await make(hub, tmp_path, "modern")
    try:
        with pytest.raises(franscor.TaskError) as err:
            await legacy.delegate("x.run", {})
        assert err.value.code == E.ENCRYPTION_REQUIRED
        assert await modern.delegate("x.run", {}) == {"ok": 1}
        assert [r["authorization"]["rule"] for r in read_log(worker.evidence.path)] == [
            "plaintext-refused", "accepted"]
    finally:
        for a in (modern, legacy, worker):
            await a.close()


async def test_unsigned_or_forged_cards_are_ignored(hub, tmp_path):
    worker = await make(hub, tmp_path, "w", [Capability("x.run", lambda: {"ok": 1})])
    boss = await make(hub, tmp_path, "b")
    try:
        # Simulate a hub that swaps the encryption key in discovery results.
        real = boss._hub_request

        async def lying_hub(type_, body, timeout):
            reply = await real(type_, body, timeout)
            if type_ == "discover":
                reply = copy.deepcopy(reply)
                for card in reply["body"]["agents"]:
                    card["enc_key"] = sealing.enc_public_b64(Identity.generate())
            return reply

        boss._hub_request = lying_hub
        assert await boss.discover("x.run") == []
        boss._hub_request = real
        assert len(await boss.discover("x.run")) == 1
    finally:
        await boss.close()
        await worker.close()
