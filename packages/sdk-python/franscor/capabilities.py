"""Capabilities: what an agent offers, how risky it is, and who handles it."""

from __future__ import annotations

import asyncio
import inspect
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

CAPABILITY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
Handler = Callable[..., Any]


def parse_risk(raw: "str | int") -> int:
    text = str(raw).strip().upper().lstrip("R")
    if text.isdigit() and 0 <= int(text) <= 5:
        return int(text)
    raise ValueError(f"risk must be R0..R5, got {raw!r}")


@dataclass
class Capability:
    name: str
    handler: Handler
    description: str = ""
    risk: int = 1
    input_schema: Optional[Dict[str, Any]] = None
    source: str = "function"
    #: Pass the input object as one argument instead of spreading a dict into kwargs.
    #: Adapters and bridges set this: their handlers take the payload as-is.
    raw_input: bool = False

    def __post_init__(self):
        if not CAPABILITY_RE.match(self.name):
            raise ValueError(f"invalid capability name {self.name!r} "
                             "(lowercase letters, digits, . _ -)")
        self.risk = parse_risk(self.risk)

    def descriptor(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"name": self.name, "description": self.description[:1000],
                               "risk": f"R{self.risk}"}
        if self.input_schema:
            out["input_schema"] = self.input_schema
        return out

    async def invoke(self, payload: Any) -> Any:
        """Dict input becomes keyword arguments; anything else is passed as-is.

        Sync handlers run in a worker thread so they never block the event loop.
        """
        if not self.raw_input and isinstance(payload, dict) and _accepts_kwargs(self.handler, payload):
            call = lambda: self.handler(**payload)  # noqa: E731
        else:
            call = lambda: self.handler(payload)  # noqa: E731
        if inspect.iscoroutinefunction(self.handler):
            return await call()
        result = await asyncio.to_thread(call)
        if inspect.isawaitable(result):
            return await result
        return result


def _accepts_kwargs(fn: Handler, payload: dict) -> bool:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return False
    params = sig.parameters.values()
    if any(p.kind is p.VAR_KEYWORD for p in params):
        return True
    named = [p for p in params if p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)]
    names = {p.name for p in named}
    required = {p.name for p in named if p.default is p.empty}
    return set(payload) <= names and required <= set(payload)


_REGISTRY: Dict[str, Capability] = {}


def capability(name: Optional[str] = None, *, description: str = "",
               risk: "str | int" = "R1",
               input_schema: Optional[Dict[str, Any]] = None
               ) -> Callable[[Handler], Handler]:
    """Declare a function as a capability. Nothing is exposed until `connect()`.

        @franscor.capability("invoice.total", risk="R1")
        def total(lines: list) -> dict: ...
    """
    def wrap(fn: Handler) -> Handler:
        cap_name = name or fn.__name__.replace("_", "-").lower()
        doc = description or (inspect.getdoc(fn) or "").split("\n\n")[0]
        _REGISTRY[cap_name] = Capability(cap_name, fn, doc, risk, input_schema)
        return fn
    return wrap


def registered() -> List[Capability]:
    return list(_REGISTRY.values())


def clear_registry() -> None:
    _REGISTRY.clear()


Approval = Callable[[Dict[str, Any]], "Awaitable[bool] | bool"]
