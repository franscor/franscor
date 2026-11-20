"""MCP bridge (Model Context Protocol, python `mcp` >= 2.3).

Export — FSP capabilities as MCP tools, e.g. for Claude Desktop or any MCP host:

    agent = await franscor.connect("mcp-gateway")
    server = franscor.bridges.mcp.build_server(agent, expose=["math.stats", "text.analyze"])
    await franscor.bridges.mcp.serve_stdio(server)          # or: franscor bridge mcp ...

Import — an MCP server's tools as FSP capabilities:

    async with await franscor.bridges.mcp.import_tools("http://localhost:8000/mcp") as tools:
        agent = await franscor.connect("files", tools=tools.capabilities)

Risk mapping (import): ``readOnlyHint`` → R1, ``destructiveHint`` → R3, otherwise
R2; override per tool with ``risk_overrides``. Export maps R0/R1 to
``readOnlyHint`` and R3+ to ``destructiveHint``.
"""

from __future__ import annotations

import json
from contextlib import AsyncExitStack
from typing import Any, Dict, Iterable, List, Optional

from .. import errors as E
from .._version import __version__
from ..capabilities import Capability
from . import ExposeError, ImportedTools, slug

try:
    import mcp_types as types
    from mcp import Client
    from mcp.server import Server
except ImportError as exc:  # pragma: no cover
    raise ImportError("the MCP bridge needs `pip install franscor[mcp]`") from exc


# -- export ---------------------------------------------------------------------

def _annotations(risk: str) -> "types.ToolAnnotations":
    level = int(str(risk).lstrip("R") or 2)
    return types.ToolAnnotations(read_only_hint=level <= 1, destructive_hint=level >= 3)


def build_server(agent, expose: "Iterable[str] | str", *, name: Optional[str] = None,
                 timeout: float = 60.0) -> "Server":
    """An MCP server whose tools are FSP capabilities reachable by `agent`.

    `expose` is an explicit list of capability names, or ``"*"`` for every
    capability visible to the agent (re-discovered on each ``tools/list``).
    Each call is ``agent.delegate(...)``: signed, policy-checked by the target,
    recorded in the target's evidence.
    """
    allow_all = expose == "*"
    allowed = set() if allow_all else set(expose)
    if not allow_all and not allowed:
        raise ExposeError("expose at least one capability, or '*' explicitly")

    async def catalogue() -> Dict[str, Dict[str, Any]]:
        found: Dict[str, Dict[str, Any]] = {}
        for card in await agent.discover():
            for cap in card.get("capabilities", []):
                if (allow_all or cap["name"] in allowed) and cap["name"] not in found:
                    found[cap["name"]] = cap
        return found

    async def list_tools(ctx, params) -> "types.ListToolsResult":
        tools = [types.Tool(name=c["name"], description=c.get("description") or c["name"],
                            input_schema=c.get("input_schema") or {"type": "object"},
                            annotations=_annotations(c.get("risk", "R2")))
                 for c in (await catalogue()).values()]
        return types.ListToolsResult(tools=tools)

    async def call_tool(ctx, params) -> "types.CallToolResult":
        tool = params.name
        if not allow_all and tool not in allowed:
            return _error(E.UNKNOWN_CAPABILITY, f"{tool} is not exposed by this bridge")
        try:
            output = await agent.delegate(tool, params.arguments or {}, timeout=timeout)
        except E.FSPError as exc:
            return _error(exc.code, exc.message)
        structured = output if isinstance(output, dict) else {"result": output}
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(output, ensure_ascii=False))],
            structured_content=structured, is_error=False)

    return Server(name or f"franscor-{agent.name}", version=__version__,
                  instructions="Tools served by FRANSCOR agents. Every call is signed, "
                               "authorized by the target agent and recorded as evidence.",
                  on_list_tools=list_tools, on_call_tool=call_tool)


def _error(code: str, message: str) -> "types.CallToolResult":
    return types.CallToolResult(content=[types.TextContent(type="text", text=f"{code}: {message}")],
                                structured_content={"error": {"code": code, "message": message}},
                                is_error=True)


async def serve_stdio(server: "Server") -> None:
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


# -- import -----------------------------------------------------------------------

def _risk_for(tool, overrides: Dict[str, int], default: int) -> int:
    if tool.name in overrides:
        return overrides[tool.name]
    ann = tool.annotations
    if ann is not None and ann.destructive_hint:
        return 3
    if ann is not None and ann.read_only_hint:
        return 1
    return default


def _decode(result) -> Any:
    if result.structured_content is not None:
        return result.structured_content
    texts = [c.text for c in result.content if getattr(c, "type", None) == "text"]
    text = "\n".join(texts)
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return {"text": text}


async def import_tools(server: Any, *, prefix: Optional[str] = None, default_risk: int = 2,
                       risk_overrides: Optional[Dict[str, int]] = None,
                       include: Optional[Iterable[str]] = None) -> ImportedTools:
    """Connect to an MCP server and wrap its tools as capabilities.

    `server` is anything `mcp.Client` accepts: a Streamable HTTP URL, a
    `StdioServerParameters`, or an in-process `Server`. Capability names are
    ``mcp.<prefix>.<tool>``; `prefix` defaults to the server's name.
    """
    stack = AsyncExitStack()
    client = await stack.enter_async_context(Client(server))
    try:
        info = client.server_info
        prefix = slug(prefix or (info.name if info else "server"), 40)
        wanted = set(include) if include is not None else None
        caps: List[Capability] = []
        cursor = None
        while True:
            page = await client.list_tools(cursor=cursor)
            for tool in page.tools:
                if wanted is not None and tool.name not in wanted:
                    continue
                caps.append(Capability(
                    name=f"mcp.{prefix}.{slug(tool.name)}"[:128],
                    handler=_caller(client, tool.name),
                    description=(tool.description or tool.name)[:1000],
                    risk=_risk_for(tool, risk_overrides or {}, default_risk),
                    input_schema=tool.input_schema or None,
                    source="mcp", raw_input=True))
            cursor = page.next_cursor
            if not cursor:
                break
    except BaseException:
        await stack.aclose()
        raise
    return ImportedTools(caps, stack)


class MCPToolError(RuntimeError):
    """The MCP server reported an error for this call."""


def _caller(client, tool_name: str):
    async def call(payload: Any = None) -> Any:
        arguments = payload if isinstance(payload, dict) else {"input": payload}
        result = await client.call_tool(tool_name, arguments)
        if result.is_error:
            raise MCPToolError(tool_name)
        return _decode(result)
    return call
