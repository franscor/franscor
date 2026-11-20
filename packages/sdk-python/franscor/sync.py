"""Blocking facade for code that is not async (scripts, Flask/Django views, notebooks
without a running loop). One private event-loop thread per agent; every call
blocks until the coroutine finishes on that thread.

    agent = franscor.connect_sync("reporter")
    print(agent.delegate("math.stats", {"values": [1, 2, 3]}))
    agent.close()
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any, Dict, List, Optional

from .client import Agent, connect


class SyncAgent:
    def __init__(self, agent: Agent, loop: asyncio.AbstractEventLoop, thread: threading.Thread):
        self._agent, self._loop, self._thread = agent, loop, thread

    def _run(self, coro, timeout: Optional[float] = None) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout)

    # read-only views
    @property
    def status(self) -> str:
        return self._agent.status

    @property
    def agent_id(self) -> str:
        return self._agent.agent_id

    @property
    def identity(self) -> Dict[str, str]:
        return self._agent.identity

    @property
    def capabilities(self) -> List[str]:
        return self._agent.capabilities

    @property
    def stats(self) -> Dict[str, Dict[str, int]]:
        return self._agent.stats

    @property
    def evidence(self):
        return self._agent.evidence

    @property
    def agent(self) -> Agent:
        """The underlying async agent (lives on the facade's loop thread)."""
        return self._agent

    def discover(self, capability: Optional[str] = None, **kw) -> List[Dict[str, Any]]:
        return self._run(self._agent.discover(capability, **kw))

    def delegate(self, capability: str, input: Any = None, **kw) -> Any:
        return self._run(self._agent.delegate(capability, input, **kw))

    def send(self, to: str, topic: str, data: Any = None) -> None:
        self._run(self._agent.send(to, topic, data))

    def rotate_key(self) -> Dict[str, Any]:
        return self._run(self._agent.rotate_key())

    def revoke_key(self, reason: str = "unspecified") -> Dict[str, Any]:
        result = self._run(self._agent.revoke_key(reason))
        self._stop()
        return result

    def close(self) -> None:
        if self._loop.is_running():
            self._run(self._agent.close(), timeout=10)
            self._stop()

    def _stop(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)

    def __enter__(self) -> "SyncAgent":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def connect_sync(*args: Any, **kwargs: Any) -> SyncAgent:
    """Same arguments as `connect()`, returns a blocking `SyncAgent`."""
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, name="franscor-loop", daemon=True)
    thread.start()
    try:
        agent = asyncio.run_coroutine_threadsafe(connect(*args, **kwargs), loop).result(60)
    except BaseException:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=5)
        raise
    return SyncAgent(agent, loop, thread)
