"""M4: MCP and A2A bridges (both directions) and OpenAI Agents / AutoGen adapters,
all against the real libraries (mcp 2.3, a2a-sdk 1.3, openai-agents 0.24, autogen-core 0.7)."""

import json

import pytest

import franscor
from franscor import errors as E
from franscor.capabilities import Capability, clear_registry
from franscor.evidence import read_log
from franscor.hub import Hub


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
    kw.setdefault("reconnect", False)
    return await franscor.connect(name, hub_url=hub.url, home=tmp_path / name, tools=list(caps), **kw)


def add(a: int, b: int) -> dict:
    return {"sum": a + b}


# -- MCP -------------------------------------------------------------------------

async def test_mcp_export_serves_fsp_capabilities(hub, tmp_path):
    mcp = pytest.importorskip("franscor.bridges.mcp")
    from mcp import Client

    worker = await make(hub, tmp_path, "worker", [
        Capability("math.add", add, "Add two integers", risk="R1",
                   input_schema={"type": "object", "properties": {"a": {"type": "integer"}}}),
        Capability("db.drop", lambda: None, "Drop the database", risk="R5")])
    gateway = await make(hub, tmp_path, "gateway")
    try:
        server = mcp.build_server(gateway, expose=["math.add", "db.drop"])
        async with Client(server) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            assert set(tools) == {"math.add", "db.drop"}
            assert tools["math.add"].annotations.read_only_hint is True
            assert tools["db.drop"].annotations.destructive_hint is True
            assert tools["math.add"].input_schema["properties"]["a"]["type"] == "integer"

            ok = await client.call_tool("math.add", {"a": 2, "b": 3})
            assert not ok.is_error and ok.structured_content == {"sum": 5}

            refused = await client.call_tool("db.drop", {})
            assert refused.is_error and refused.structured_content["error"]["code"] == E.APPROVAL_REJECTED

            hidden = await client.call_tool("anything.else", {})
            assert hidden.is_error and hidden.structured_content["error"]["code"] == E.UNKNOWN_CAPABILITY
        # The worker's evidence names the gateway as requester.
        records = read_log(worker.evidence.path)
        assert {r["execution"]["requester"] for r in records} == {gateway.agent_id}
        assert [r["execution"]["status"] for r in records] == ["executed", "approval_rejected"]
    finally:
        await gateway.close()
        await worker.close()


async def test_mcp_export_requires_explicit_exposure(hub, tmp_path):
    mcp = pytest.importorskip("franscor.bridges.mcp")
    from franscor.bridges import ExposeError

    gateway = await make(hub, tmp_path, "gateway")
    try:
        with pytest.raises(ExposeError):
            mcp.build_server(gateway, expose=[])
    finally:
        await gateway.close()


async def test_mcp_import_turns_tools_into_capabilities(hub, tmp_path):
    mcp = pytest.importorskip("franscor.bridges.mcp")
    import mcp_types as t
    from mcp.server import Server

    async def list_tools(ctx, params):
        return t.ListToolsResult(tools=[
            t.Tool(name="read_note", description="Read a note", input_schema={"type": "object"},
                   annotations=t.ToolAnnotations(read_only_hint=True)),
            t.Tool(name="delete_note", description="Delete a note", input_schema={"type": "object"},
                   annotations=t.ToolAnnotations(destructive_hint=True)),
            t.Tool(name="broken", description="Always fails", input_schema={"type": "object"})])

    async def call_tool(ctx, params):
        if params.name == "broken":
            return t.CallToolResult(content=[t.TextContent(type="text", text="disk on fire")], is_error=True)
        if params.name == "read_note":
            return t.CallToolResult(content=[t.TextContent(type="text", text=json.dumps({"note": params.arguments["id"]}))])
        return t.CallToolResult(content=[], structured_content={"deleted": params.arguments["id"]})

    server = Server("notes", on_list_tools=list_tools, on_call_tool=call_tool)
    async with await mcp.import_tools(server) as imported:
        caps = {c.name: c.risk for c in imported.capabilities}
        assert caps == {"mcp.notes.read_note": 1, "mcp.notes.delete_note": 3, "mcp.notes.broken": 2}
        notes = await make(hub, tmp_path, "notes", imported.capabilities)
        boss = await make(hub, tmp_path, "boss")
        try:
            assert await boss.delegate("mcp.notes.read_note", {"id": 7}) == {"note": 7}
            assert await boss.delegate("mcp.notes.delete_note", {"id": 7}) == {"deleted": 7}
            with pytest.raises(franscor.TaskError) as err:
                await boss.delegate("mcp.notes.broken", {})
            assert err.value.status == "failed" and "fire" not in err.value.message
        finally:
            await boss.close()
            await notes.close()


# -- A2A -------------------------------------------------------------------------

async def test_a2a_round_trip_through_both_bridges(hub, tmp_path):
    """boss --FSP--> caller --A2A/HTTP--> gateway --FSP--> worker."""
    a2a = pytest.importorskip("franscor.bridges.a2a")
    import httpx

    worker = await make(hub, tmp_path, "worker", [
        Capability("math.add", add, "Add two integers", risk="R1"),
        Capability("db.drop", lambda: None, "Drop", risk="R5")])
    gateway = await make(hub, tmp_path, "gateway")
    boss = await make(hub, tmp_path, "boss")
    app = await a2a.A2AGateway(gateway, ["math.add", "db.drop"], base_url="http://bridge",
                               token="s3cret").app()
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://bridge") as anon:
            card = (await anon.get("/.well-known/agent-card.json")).json()
            assert [s["id"] for s in card["skills"]] == ["math.add", "db.drop"]
            denied = await anon.post("/a2a", json={"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {}})
            assert denied.status_code == 401

        async with httpx.AsyncClient(transport=transport, base_url="http://bridge",
                                     headers={"Authorization": "Bearer s3cret"}) as authed:
            async with await a2a.import_agent("http://bridge", httpx_client=authed) as remote:
                assert sorted(c.name for c in remote.capabilities) == [
                    "a2a.franscor-gateway.db.drop", "a2a.franscor-gateway.math.add"]
                caller = await make(hub, tmp_path, "caller", remote.capabilities)
                try:
                    out = await boss.delegate("a2a.franscor-gateway.math.add", {"a": 40, "b": 2})
                    assert out == {"sum": 42} and isinstance(out["sum"], int)
                    with pytest.raises(franscor.TaskError) as err:
                        await boss.delegate("a2a.franscor-gateway.db.drop", {})
                    assert err.value.status == "failed"
                finally:
                    await caller.close()
        statuses = [r["execution"]["status"] for r in read_log(worker.evidence.path)]
        assert statuses == ["executed", "approval_rejected"]
    finally:
        await boss.close()
        await gateway.close()
        await worker.close()


# -- framework adapters ----------------------------------------------------------

async def test_openai_agents_function_tools(hub, tmp_path):
    agents = pytest.importorskip("agents")

    @agents.function_tool
    def convert(celsius: float) -> str:
        """Convert Celsius to Fahrenheit."""
        return f"{celsius * 9 / 5 + 32:.1f}F"

    assistant = agents.Agent(name="weather", instructions="-", tools=[convert])
    worker = await make(hub, tmp_path, "w", [assistant])
    boss = await make(hub, tmp_path, "b")
    try:
        assert worker.capabilities == ["tool.convert"]
        assert [a["adapter"] for a in worker.adapters if a.get("active")] == ["openai-agents"]
        assert await boss.delegate("tool.convert", {"celsius": 100}) == "212.0F"
    finally:
        await boss.close()
        await worker.close()


async def test_autogen_function_tools(hub, tmp_path):
    tools = pytest.importorskip("autogen_core.tools")

    def multiply(a: int, b: int) -> int:
        return a * b

    worker = await make(hub, tmp_path, "w", [tools.FunctionTool(multiply, description="Multiply")])
    boss = await make(hub, tmp_path, "b")
    try:
        assert worker.capabilities == ["tool.multiply"]
        card = worker.card["capabilities"][0]
        assert card["description"] == "Multiply" and "a" in card["input_schema"]["properties"]
        assert await boss.delegate("tool.multiply", {"a": 6, "b": 7}) == 42
    finally:
        await boss.close()
        await worker.close()


async def test_mcp_bridge_cli_over_real_stdio(hub, tmp_path):
    """What an MCP host (e.g. a desktop assistant) runs: `franscor bridge mcp` as a subprocess."""
    pytest.importorskip("franscor.bridges.mcp")
    import os
    import sys

    from mcp import Client
    from mcp.client.stdio import StdioServerParameters

    worker = await make(hub, tmp_path, "worker", [Capability("math.add", add, "Add", risk="R1")])
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "franscor.cli", "bridge", "mcp", "--hub", hub.url, "--expose", "math.add",
              "--name", "desktop-bridge"],
        env={**os.environ, "FRANSCOR_HOME": str(tmp_path / "bridge")})
    try:
        async with Client(params) as client:
            assert [t.name for t in (await client.list_tools()).tools] == ["math.add"]
            result = await client.call_tool("math.add", {"a": 20, "b": 22})
            assert result.structured_content == {"sum": 42}
    finally:
        await worker.close()
