"""Adapter engine.

An adapter turns something that already exists in the developer's process
(decorated functions, LangChain tools, a compiled LangGraph graph…) into
FSP capabilities, without changing that code. Adapters are isolated: one
that fails is reported in `agent.adapters` and skipped, never fatal.

Third-party adapters register under the entry-point group
`franscor.adapters` and are loaded at `connect()` time (never at install
time). Disable with `connect(load_plugins=False)`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib import metadata
from typing import Any, Dict, List, Protocol, runtime_checkable

from ..capabilities import Capability, registered

ENTRY_POINT_GROUP = "franscor.adapters"


@dataclass
class AdapterContext:
    objects: List[Any] = field(default_factory=list)
    detection: Dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class Adapter(Protocol):
    name: str
    version: str

    def detect(self, ctx: AdapterContext) -> bool: ...

    def capabilities(self, ctx: AdapterContext) -> List[Capability]: ...


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", text.lower()).strip("-.")
    return slug[:100] or "tool"


class FunctionAdapter:
    """Functions declared with `@franscor.capability`."""

    name, version = "functions", "0.1.0"

    def detect(self, ctx: AdapterContext) -> bool:
        return bool(registered()) or any(isinstance(o, Capability) for o in ctx.objects)

    def capabilities(self, ctx: AdapterContext) -> List[Capability]:
        return registered() + [o for o in ctx.objects if isinstance(o, Capability)]


def _is_runnable_tool(obj: Any) -> bool:
    return (isinstance(getattr(obj, "name", None), str)
            and (callable(getattr(obj, "ainvoke", None)) or callable(getattr(obj, "invoke", None)))
            and not isinstance(obj, Capability)
            # each object belongs to exactly one adapter
            and not _is_openai_function_tool(obj) and not _is_autogen_tool(obj))


class LangChainAdapter:
    """LangChain tools and runnables (including compiled LangGraph graphs).

    Duck-typed on the public Runnable interface (`name` + `ainvoke`/`invoke`),
    so it works across LangChain versions without importing LangChain.
    Unknown tools default to risk R2; override with `risk_overrides`.
    """

    name, version = "langchain", "0.1.0"

    def __init__(self, default_risk: int = 2, risk_overrides: Dict[str, int] | None = None):
        self.default_risk = default_risk
        self.risk_overrides = risk_overrides or {}

    def detect(self, ctx: AdapterContext) -> bool:
        return any(_is_runnable_tool(o) for o in ctx.objects)

    def capabilities(self, ctx: AdapterContext) -> List[Capability]:
        caps = []
        for obj in ctx.objects:
            if not _is_runnable_tool(obj):
                continue
            cap_name = "tool." + _slug(obj.name)
            caps.append(Capability(
                name=cap_name,
                handler=_runnable_handler(obj),
                description=str(getattr(obj, "description", "") or "")[:1000],
                risk=self.risk_overrides.get(cap_name, self.default_risk),
                input_schema=_schema_of(obj),
                source=self.name,
                raw_input=True,
            ))
        return caps


def _runnable_handler(obj: Any):
    if callable(getattr(obj, "ainvoke", None)):
        async def run(payload: Any) -> Any:
            return await obj.ainvoke(payload)
    else:
        def run(payload: Any) -> Any:  # type: ignore[misc]
            return obj.invoke(payload)
    return run


def _schema_of(obj: Any):
    schema = getattr(obj, "args_schema", None)
    for attr in ("model_json_schema", "schema"):
        fn = getattr(schema, attr, None)
        if callable(fn):
            try:
                result = fn()
                return result if isinstance(result, dict) else None
            except Exception:
                return None
    return None


def _is_openai_function_tool(obj: Any) -> bool:
    return (isinstance(getattr(obj, "name", None), str)
            and callable(getattr(obj, "on_invoke_tool", None))
            and isinstance(getattr(obj, "params_json_schema", None), dict))


class OpenAIAgentsAdapter:
    """OpenAI Agents SDK `FunctionTool`s (from `@function_tool`), duck-typed on
    `name`, `params_json_schema` and `on_invoke_tool(ctx, json_args)`.
    Also accepts an `agents.Agent`: its function tools are adapted.
    The tool's own guardrails and failure handling run as in the SDK."""

    name, version = "openai-agents", "0.1.0"

    def __init__(self, default_risk: int = 2, risk_overrides: Dict[str, int] | None = None):
        self.default_risk = default_risk
        self.risk_overrides = risk_overrides or {}

    def _tools(self, ctx: AdapterContext) -> list:
        out = []
        for obj in ctx.objects:
            if _is_openai_function_tool(obj):
                out.append(obj)
            elif type(obj).__module__.startswith("agents") and isinstance(getattr(obj, "tools", None), list):
                out.extend(t for t in obj.tools if _is_openai_function_tool(t))
        return out

    def detect(self, ctx: AdapterContext) -> bool:
        return bool(self._tools(ctx))

    def capabilities(self, ctx: AdapterContext) -> List[Capability]:
        caps = []
        for tool in self._tools(ctx):
            cap_name = "tool." + _slug(tool.name)
            caps.append(Capability(
                name=cap_name, handler=_openai_handler(tool),
                description=str(getattr(tool, "description", "") or "")[:1000],
                risk=self.risk_overrides.get(cap_name, self.default_risk),
                input_schema=tool.params_json_schema, source=self.name, raw_input=True))
        return caps


def _openai_handler(tool: Any):
    import json as _json

    async def run(payload: Any) -> Any:
        from agents.tool_context import ToolContext  # only reached when the SDK is installed

        args = _json.dumps(payload if isinstance(payload, dict) else {"input": payload})
        ctx = ToolContext(context=None, tool_name=tool.name, tool_call_id="franscor", tool_arguments=args)
        return await tool.on_invoke_tool(ctx, args)
    return run


def _is_autogen_tool(obj: Any) -> bool:
    return (isinstance(getattr(obj, "name", None), str)
            and callable(getattr(obj, "run_json", None))
            and isinstance(getattr(obj, "schema", None), dict))


class AutoGenAdapter:
    """AutoGen (`autogen_core.tools.BaseTool`, e.g. `FunctionTool`), duck-typed on
    `name`, `schema` and `run_json(args, cancellation_token)`."""

    name, version = "autogen", "0.1.0"

    def __init__(self, default_risk: int = 2, risk_overrides: Dict[str, int] | None = None):
        self.default_risk = default_risk
        self.risk_overrides = risk_overrides or {}

    def detect(self, ctx: AdapterContext) -> bool:
        return any(_is_autogen_tool(o) for o in ctx.objects)

    def capabilities(self, ctx: AdapterContext) -> List[Capability]:
        caps = []
        for tool in (o for o in ctx.objects if _is_autogen_tool(o)):
            cap_name = "tool." + _slug(tool.name)
            caps.append(Capability(
                name=cap_name, handler=_autogen_handler(tool),
                description=str(tool.schema.get("description") or getattr(tool, "description", ""))[:1000],
                risk=self.risk_overrides.get(cap_name, self.default_risk),
                input_schema=tool.schema.get("parameters"), source=self.name, raw_input=True))
        return caps


def _autogen_handler(tool: Any):
    async def run(payload: Any) -> Any:
        from autogen_core import CancellationToken  # only reached when autogen-core is installed

        args = payload if isinstance(payload, dict) else {"input": payload}
        result = await tool.run_json(args, CancellationToken())
        # Tools may return pydantic models or other objects: keep JSON as-is, else stringify.
        if isinstance(result, (dict, list, str, int, float, bool)) or result is None:
            return result
        dump = getattr(result, "model_dump", None)
        return dump(mode="json") if callable(dump) else tool.return_value_as_string(result)
    return run


BUILTIN = (FunctionAdapter, OpenAIAgentsAdapter, AutoGenAdapter, LangChainAdapter)


def load_adapters(load_plugins: bool = True) -> tuple[list, list]:
    """Return (adapters, load_errors)."""
    adapters: list = [cls() for cls in BUILTIN]
    errors: list = []
    if load_plugins:
        for ep in metadata.entry_points(group=ENTRY_POINT_GROUP):
            try:
                factory = ep.load()
                adapter = factory() if callable(factory) else factory
                if not isinstance(adapter, Adapter):
                    raise TypeError("does not implement the Adapter protocol")
                adapters.append(adapter)
            except Exception as exc:  # isolation: a broken plugin is reported, not fatal
                errors.append({"adapter": ep.name, "error": f"{type(exc).__name__}: {exc}"})
    return adapters, errors


def collect(ctx: AdapterContext, adapters: list) -> tuple[Dict[str, Capability], list]:
    caps: Dict[str, Capability] = {}
    report = []
    for adapter in adapters:
        entry = {"adapter": adapter.name, "version": adapter.version, "active": False}
        try:
            if adapter.detect(ctx):
                found = adapter.capabilities(ctx)
                for cap in found:
                    if cap.name in caps:
                        raise ValueError(f"duplicate capability {cap.name!r}")
                    caps[cap.name] = cap
                entry.update(active=True, capabilities=[c.name for c in found])
        except Exception as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"
        report.append(entry)
    return caps, report
