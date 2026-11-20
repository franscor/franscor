import asyncio
import json

import pytest

import franscor
from franscor import errors as E
from franscor.capabilities import Capability, clear_registry
from franscor.evidence import read_log, verify_chain
from franscor.hub import Hub
from franscor.identity import Identity


@pytest.fixture
async def hub():
    h = await Hub("127.0.0.1", 0).start()
    yield h
    await h.stop()


@pytest.fixture(autouse=True)
def _clean():
    clear_registry()
    yield
    clear_registry()


async def make(hub, tmp_path, name, caps=(), **kw):
    kw.setdefault("load_plugins", False)
    return await franscor.connect(name, hub_url=hub.url, home=tmp_path / name,
                                  tools=list(caps), reconnect=False, **kw)


async def test_discover_delegate_and_evidence(hub, tmp_path):
    calls = []

    def add(a: int, b: int) -> dict:
        calls.append((a, b))
        return {"sum": a + b, "ratio": a / b}

    worker = await make(hub, tmp_path, "worker", [Capability("math.add", add, "add", risk="R1")])
    boss = await make(hub, tmp_path, "boss")
    try:
        found = await boss.discover("math.add")
        assert [a["agent_id"] for a in found] == [worker.agent_id]
        assert await boss.delegate("math.add", {"a": 3, "b": 4}) == {"sum": 7, "ratio": 0.75}
        assert calls == [(3, 4)]
        records = read_log(worker.evidence.path)
        assert verify_chain(records, worker.identity["public_key"]).valid
        assert records[-1]["execution"]["status"] == "executed"
        assert records[-1]["execution"]["requester"] == boss.agent_id
        assert '"a"' not in json.dumps(records[-1]) and '"sum"' not in json.dumps(records[-1])
    finally:
        await boss.close()
        await worker.close()


async def test_other_org_is_invisible_and_denied(hub, tmp_path):
    worker = await make(hub, tmp_path, "worker", [Capability("x.run", lambda: {"ok": True})], org="acme")
    outsider = await make(hub, tmp_path, "outsider", org="globex")
    try:
        assert await outsider.discover("x.run") == []
        with pytest.raises(franscor.TaskError) as err:
            await outsider.delegate("x.run", {}, to=worker.agent_id, timeout=3)
        assert err.value.code == E.OFFLINE  # existence not leaked
    finally:
        await outsider.close()
        await worker.close()


async def test_public_agent_still_enforces_accepts(hub, tmp_path):
    worker = await make(hub, tmp_path, "worker", [Capability("x.run", lambda: {"ok": True})],
                        org="acme", visibility="public")
    outsider = await make(hub, tmp_path, "outsider", org="globex")
    try:
        assert len(await outsider.discover("x.run")) == 1
        with pytest.raises(franscor.TaskError) as err:
            await outsider.delegate("x.run", {}, timeout=3)
        assert err.value.code == E.DENIED
    finally:
        await outsider.close()
        await worker.close()


async def test_receiver_policy_is_the_boundary(hub, tmp_path):
    # The hub is permissive here (accept "*"), the receiver's own policy is not.
    worker = await make(hub, tmp_path, "worker", [Capability("x.run", lambda: {"ok": True})],
                        org="acme", visibility="public", accept_orgs=["*"])
    worker.policy.accept_orgs = ["acme"]
    outsider = await make(hub, tmp_path, "outsider", org="globex")
    try:
        with pytest.raises(franscor.TaskError) as err:
            await outsider.delegate("x.run", {}, timeout=3)
        assert err.value.status == "rejected" and err.value.code == E.DENIED
        assert read_log(worker.evidence.path)[-1]["execution"]["status"] == "blocked"
    finally:
        await outsider.close()
        await worker.close()


async def test_high_risk_needs_approval(hub, tmp_path):
    decisions = []

    async def approve(info):
        decisions.append(info["capability"])
        return info["input"]["amount"] < 100

    pay = Capability("pay.send", lambda amount: {"sent": amount}, risk="R4")
    worker = await make(hub, tmp_path, "bank", [pay], approval=approve)
    boss = await make(hub, tmp_path, "boss")
    try:
        assert await boss.delegate("pay.send", {"amount": 10}) == {"sent": 10}
        with pytest.raises(franscor.TaskError) as err:
            await boss.delegate("pay.send", {"amount": 1000})
        assert err.value.status == "approval_rejected"
        assert decisions == ["pay.send", "pay.send"]
        statuses = [r["execution"]["status"] for r in read_log(worker.evidence.path)]
        assert statuses == ["executed", "approval_rejected"]
    finally:
        await boss.close()
        await worker.close()


async def test_no_handler_means_no_approval(hub, tmp_path):
    worker = await make(hub, tmp_path, "w", [Capability("db.drop", lambda: None, risk="R5")])
    boss = await make(hub, tmp_path, "b")
    try:
        with pytest.raises(franscor.TaskError) as err:
            await boss.delegate("db.drop", {})
        assert err.value.code == E.APPROVAL_REJECTED
    finally:
        await boss.close()
        await worker.close()


async def test_timeout_unknown_capability_and_failure(hub, tmp_path):
    async def slow():
        await asyncio.sleep(5)

    def boom():
        raise RuntimeError("secret detail")

    worker = await make(hub, tmp_path, "w", [Capability("slow", slow), Capability("boom", boom)])
    boss = await make(hub, tmp_path, "b")
    try:
        with pytest.raises(franscor.TaskError) as err:
            await boss.delegate("slow", {}, timeout=0.5, retries=0)
        assert err.value.status == "timeout"
        with pytest.raises(franscor.TaskError) as err:
            await boss.delegate("nope", {}, to=worker.agent_id, timeout=3)
        assert err.value.code == E.UNKNOWN_CAPABILITY
        with pytest.raises(franscor.TaskError) as err:
            await boss.delegate("boom", {})
        assert err.value.status == "failed" and "secret" not in err.value.message
    finally:
        await boss.close()
        await worker.close()


async def test_retry_is_idempotent(hub, tmp_path):
    count = 0

    async def once():
        nonlocal count
        count += 1
        await asyncio.sleep(0.8)
        return {"n": count}

    worker = await make(hub, tmp_path, "w", [Capability("once", once)])
    boss = await make(hub, tmp_path, "b")
    try:
        # First attempt times out at 0.5 s, retry reuses the task id: executed once.
        assert await boss.delegate("once", {}, timeout=0.5, retries=3) == {"n": 1}
        assert count == 1
    finally:
        await boss.close()
        await worker.close()


async def test_messages_and_forged_registration(hub, tmp_path):
    got = asyncio.get_running_loop().create_future()
    a = await make(hub, tmp_path, "a")
    b = await make(hub, tmp_path, "b")

    @b.on_message("ping")
    def _ping(data, sender):
        got.set_result((data, sender["agent_id"]))

    try:
        await a.send(b.agent_id, "ping", {"x": 1})
        assert await asyncio.wait_for(got, 3) == ({"x": 1}, a.agent_id)
        # Registering with someone else's key but our signature fails.
        with pytest.raises(franscor.FSPError):
            await franscor.connect("c", hub_url=hub.url, home=tmp_path / "c",
                                   identity=_Spoof(b.identity["public_key"]),
                                   reconnect=False, load_plugins=False)
    finally:
        await a.close()
        await b.close()


class _Spoof(Identity):
    """Claims a victim's public key but can only sign with its own key."""

    def __init__(self, victim_pem):
        real = Identity.generate()
        object.__setattr__(self, "_key", real.private_key)
        object.__setattr__(self, "public_pem", victim_pem)
        from franscor.identity import agent_id_from_pem, kid_from_pem
        object.__setattr__(self, "agent_id", agent_id_from_pem(victim_pem))
        object.__setattr__(self, "kid", kid_from_pem(victim_pem))


async def test_insecure_remote_hub_refused(tmp_path):
    with pytest.raises(ValueError):
        await franscor.connect("x", hub_url="ws://example.com:7700", home=tmp_path)


class _FakeTool:
    """Stand-in with the public LangChain Runnable surface (name, description, ainvoke)."""

    name = "Web Search"
    description = "search the web"

    async def ainvoke(self, payload):
        return {"hits": [payload["q"]]}


async def test_langchain_style_tools_are_adapted(hub, tmp_path):
    worker = await make(hub, tmp_path, "w", [_FakeTool()])
    boss = await make(hub, tmp_path, "b")
    try:
        assert worker.capabilities == ["tool.web-search"]
        assert [a["adapter"] for a in worker.adapters if a["active"]] == ["langchain"]
        assert await boss.delegate("tool.web-search", {"q": "fsp"}) == {"hits": ["fsp"]}
    finally:
        await boss.close()
        await worker.close()
