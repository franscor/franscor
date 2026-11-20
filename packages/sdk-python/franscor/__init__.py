"""FRANSCOR — secure interoperability layer for AI agents.

    import franscor

    @franscor.capability("text.upper", risk="R0")
    def upper(text: str) -> dict:
        return {"text": text.upper()}

    agent = await franscor.connect("writer")
    print(agent.status, agent.identity["agent_id"], agent.capabilities)
    result = await agent.delegate("math.add", {"a": 2, "b": 3})
"""

from ._version import FSP_VERSION, __version__
from .capabilities import Capability, capability
from .client import Agent, connect
from .detect import detect
from .errors import FSPError, TaskError
from .identity import Identity
from .keystore import FileKeyStore, KeyringKeyStore
from .statements import make_revocation, make_rotation, verify_revocation, verify_rotation
from .sync import SyncAgent, connect_sync

__all__ = ["Agent", "Capability", "FSPError", "FSP_VERSION", "FileKeyStore", "Identity",
           "KeyringKeyStore", "SyncAgent", "TaskError", "__version__", "capability", "connect",
           "connect_sync", "detect", "make_revocation", "make_rotation", "verify_revocation",
           "verify_rotation"]
