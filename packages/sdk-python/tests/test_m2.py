"""M2 hardening: key rotation/revocation, key stores, sync facade, telemetry, stats,
and the LangChain adapter against the real libraries."""

import asyncio
import copy
import json

import pytest

import franscor
from franscor import errors as E
from franscor.capabilities import Capability, clear_registry
from franscor.evidence import read_log, verify_chain
from franscor.hub import Hub
from franscor.identity import Identity
from franscor.keystore import FileKeyStore, KeyringKeyStore
from franscor.statements import make_revocation, make_rotation, verify_revocation, verify_rotation


@pytest.fixture
async def hub(tmp_path):
    h = await Hub("127.0.0.1", 0, revocations=tmp_path / "revocations.jsonl").start()
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


# -- statements ---------------------------------------------------------------

def test_statements_verify_and_detect_tampering():
    old, new, other = Identity.generate(), Identity.generate(), Identity.generate()
    rot = make_rotation(old, new)
    verify_rotation(rot)
    for field, value in (("new_public_key", other.public_pem), ("ts", rot["ts"] + 1)):
        bad = copy.deepcopy(rot)
        bad[field] = value
        with pytest.raises(E.FSPError):
            verify_rotation(bad)
    # Signed by the old key only (attacker without the new key's cooperation): refused.
    forged = copy.deepcopy(rot)
    forged["sigs"]["new"] = forged["sigs"]["old"]
    with pytest.raises(E.FSPError):
        verify_rotation(forged)
    rev = make_revocation(old, "laptop stolen")
    verify_revocation(rev)
    rev["reason"] = "nothing happened"
    with pytest.raises(E.FSPError):
        verify_revocation(rev)


# -- rotation / revocation over the hub ---------------------------------------

async def test_rotation_moves_the_agent_to_a_new_id(hub, tmp_path):
    worker = await make(hub, tmp_path, "worker", [Capability("x.run", lambda: {"ok": 1})])
    boss = await make(hub, tmp_path, "boss")
    try:
        old_id = worker.agent_id
        assert await boss.delegate("x.run", {}) == {"ok": 1}
        statement = await worker.rotate_key()
        assert statement["old_agent_id"] == old_id and worker.agent_id != old_id
        assert worker.status == "connected"
        assert [a["agent_id"] for a in await boss.discover("x.run")] == [worker.agent_id]
        assert await boss.delegate("x.run", {}) == {"ok": 1}
        # The key on disk is the new one; the old key is kept for attribution.
        store = FileKeyStore(tmp_path / "worker")
        assert Identity.from_private_pem(store.load("worker")).agent_id == worker.agent_id
        assert any(p.name.startswith("worker.key.rotated-") for p in store.path("worker").parent.iterdir())
        # The hub persisted the statement; the old key can no longer register.
        lines = (tmp_path / "revocations.jsonl").read_text("utf-8").splitlines()
        assert json.loads(lines[0])["old_agent_id"] == old_id
        old = Identity.from_private_pem(
            next(p for p in store.path("worker").parent.iterdir() if "rotated" in p.name).read_bytes())
        with pytest.raises(franscor.FSPError) as err:
            await make(hub, tmp_path, "ghost", identity=old)
        assert err.value.code == E.REVOKED
        # Evidence continues in a new chain signed by the new key.
        assert verify_chain(read_log(worker.evidence.path), worker.identity["public_key"]).valid
    finally:
        await boss.close()
        await worker.close()


async def test_revocation_survives_hub_restart(tmp_path):
    path = tmp_path / "rev.jsonl"
    h1 = await Hub("127.0.0.1", 0, revocations=path).start()
    ident = Identity.generate()
    agent = await franscor.connect("w", hub_url=h1.url, home=tmp_path, identity=ident,
                                   load_plugins=False, reconnect=False)
    await agent.revoke_key("compromised")
    assert agent.status == "closed"
    await h1.stop()
    h2 = await Hub("127.0.0.1", 0, revocations=path).start()
    try:
        assert ident.agent_id in h2.revoked
        with pytest.raises(franscor.FSPError) as err:
            await franscor.connect("w", hub_url=h2.url, home=tmp_path, identity=ident,
                                   load_plugins=False, reconnect=False)
        assert err.value.code == E.REVOKED
    finally:
        await h2.stop()


async def test_cannot_revoke_someone_else(hub, tmp_path):
    victim = Identity.generate()
    attacker = await make(hub, tmp_path, "attacker")
    try:
        with pytest.raises(franscor.FSPError) as err:
            await attacker._hub_request("identity.revoke",
                                        {"statement": make_revocation(victim)}, 5)
        assert err.value.code == E.ID_MISMATCH
        assert victim.agent_id not in hub.revoked
    finally:
        await attacker.close()


async def test_offline_revocation_file_is_verified(tmp_path):
    good = make_revocation(Identity.generate())
    bad = make_revocation(Identity.generate())
    bad["reason"] = "edited"
    path = tmp_path / "rev.jsonl"
    path.write_text(json.dumps(good) + "\n" + json.dumps(bad) + "\n", "utf-8")
    with pytest.raises(franscor.FSPError):
        Hub("127.0.0.1", 0, revocations=path)


# -- key stores ---------------------------------------------------------------

class _MemoryKeyring:
    def __init__(self):
        self.data = {}

    def get_password(self, service, user):
        return self.data.get((service, user))

    def set_password(self, service, user, value):
        self.data[(service, user)] = value


def test_keyring_store_roundtrip_and_rotation():
    backend = _MemoryKeyring()
    store = KeyringKeyStore(backend=backend)
    first = Identity.load_or_create("agent", store=store)
    assert Identity.load_or_create("agent", store=store).agent_id == first.agent_id
    second = Identity.generate()
    second.save("agent", store, replace=True)
    assert Identity.load_or_create("agent", store=store).agent_id == second.agent_id
    assert any(user.startswith("agent.rotated-") for (_, user) in backend.data)
    assert all("PRIVATE KEY" in v for v in backend.data.values())


def test_file_store_never_overwrites_silently(tmp_path):
    store = FileKeyStore(tmp_path)
    Identity.load_or_create("a", store=store)
    with pytest.raises(FileExistsError):
        Identity.generate().save("a", store)


def test_passphrase_encrypts_key_at_rest(tmp_path, monkeypatch):
    monkeypatch.setenv("FRANSCOR_KEY_PASSPHRASE", "correct horse")
    store = FileKeyStore(tmp_path)
    ident = Identity.load_or_create("p", store=store)
    assert b"ENCRYPTED" in store.load("p")
    assert Identity.load_or_create("p", store=store).agent_id == ident.agent_id
    monkeypatch.setenv("FRANSCOR_KEY_PASSPHRASE", "wrong")
    with pytest.raises(ValueError):
        Identity.load_or_create("p", store=store)


# -- sync facade, stats -------------------------------------------------------

async def test_connect_sync_from_blocking_code(hub, tmp_path):
    worker = await make(hub, tmp_path, "worker", [Capability("x.double", lambda n: {"n": n * 2})])

    def blocking_client():
        with franscor.connect_sync("sync-client", hub_url=hub.url, home=tmp_path / "s",
                                   load_plugins=False) as agent:
            assert agent.status == "connected"
            peers = agent.discover("x.double")
            out = agent.delegate("x.double", {"n": 21})
            return peers, out, dict(agent.stats["delegated"])

    try:
        peers, out, stats = await asyncio.to_thread(blocking_client)
        assert [p["agent_id"] for p in peers] == [worker.agent_id]
        assert out == {"n": 42} and stats == {"completed": 1}
        assert worker.stats["served"] == {"completed": 1}
    finally:
        await worker.close()


# -- OpenTelemetry --------------------------------------------------------------

@pytest.fixture(scope="module")
def spans():
    sdk = pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry import trace
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = sdk.TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return exporter


async def test_trace_context_crosses_agents(hub, tmp_path, spans):
    spans.clear()
    worker = await make(hub, tmp_path, "w", [Capability("x.run", lambda secret: {"ok": 1}, risk="R1")])
    boss = await make(hub, tmp_path, "b")
    try:
        await boss.delegate("x.run", {"secret": "do-not-trace"})
        await asyncio.sleep(0.05)
    finally:
        await boss.close()
        await worker.close()
    by_name = {s.name: s for s in spans.get_finished_spans()}
    client, server = by_name["franscor.delegate"], by_name["franscor.task"]
    assert server.context.trace_id == client.context.trace_id
    assert server.parent.span_id == client.context.span_id
    assert server.attributes["franscor.status"] == "completed"
    assert "do-not-trace" not in json.dumps({k: str(v) for s in (client, server) for k, v in s.attributes.items()})


# -- real LangChain / LangGraph --------------------------------------------------

async def test_real_langchain_tool_and_langgraph_graph(hub, tmp_path):
    tools = pytest.importorskip("langchain_core.tools")
    graph_mod = pytest.importorskip("langgraph.graph")
    from typing import TypedDict

    @tools.tool
    def word_count(text: str) -> int:
        """Count words in a text."""
        return len(text.split())

    class State(TypedDict):
        n: int

    builder = graph_mod.StateGraph(State)
    builder.add_node("inc", lambda s: {"n": s["n"] + 1})
    builder.add_edge(graph_mod.START, "inc")
    builder.add_edge("inc", graph_mod.END)
    graph = builder.compile(name="counter")

    worker = await make(hub, tmp_path, "lc", [word_count, graph])
    boss = await make(hub, tmp_path, "boss")
    try:
        assert worker.capabilities == ["tool.counter", "tool.word_count"]
        card = next(c for c in worker.card["capabilities"] if c["name"] == "tool.word_count")
        assert card["risk"] == "R2" and "text" in card["input_schema"]["properties"]
        assert await boss.delegate("tool.word_count", {"text": "three little words"}) == 3
        assert await boss.delegate("tool.counter", {"n": 41}) == {"n": 42}
    finally:
        await boss.close()
        await worker.close()
