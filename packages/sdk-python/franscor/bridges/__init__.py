"""Bridges to other agent protocols. Each direction is explicit:

* **export** — make capabilities reachable on the FSP network available to an
  MCP client (`mcp.serve`) or to A2A clients (`a2a.A2AGateway`). The bridge is
  itself an FSP agent: every call is a signed delegation, the target agent's
  policy applies, and evidence is written as usual. Only the capabilities you
  list are exposed.
* **import** — turn the tools of an MCP server or the skills of an A2A agent
  into FSP capabilities (`mcp.import_tools`, `a2a.import_agent`), then pass them
  to `connect(tools=...)`.

Optional dependencies: ``pip install franscor[mcp]`` / ``franscor[a2a]``.
"""

from __future__ import annotations

import re
from typing import Any

from ..capabilities import Capability


def slug(text: str, limit: int = 60) -> str:
    out = re.sub(r"[^a-z0-9._-]+", "-", str(text).lower()).strip("-.")
    return out[:limit] or "x"


def normalize_numbers(value: Any) -> Any:
    """Protobuf `Value` stores every number as a double: 2 comes back as 2.0.
    Restore integral values so handlers and hashes see what was sent."""
    if isinstance(value, float) and value.is_integer() and abs(value) <= 2**53 - 1:
        return int(value)
    if isinstance(value, list):
        return [normalize_numbers(v) for v in value]
    if isinstance(value, dict):
        return {k: normalize_numbers(v) for k, v in value.items()}
    return value


class ImportedTools:
    """Capabilities backed by a live remote session. Keep it open while the agent runs."""

    def __init__(self, capabilities: list[Capability], stack):
        self.capabilities = capabilities
        self._stack = stack

    async def aclose(self) -> None:
        await self._stack.aclose()

    async def __aenter__(self) -> "ImportedTools":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()


class ExposeError(ValueError):
    """A bridge was asked to expose nothing, or something it cannot see."""
