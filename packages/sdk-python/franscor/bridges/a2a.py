"""A2A bridge (Agent2Agent protocol 1.0, python `a2a-sdk` >= 1.3, JSON-RPC binding).

Export — FSP capabilities as skills of an A2A agent:

    agent = await franscor.connect("a2a-gateway")
    gateway = A2AGateway(agent, expose=["math.stats"], base_url="http://127.0.0.1:8800",
                         token=os.environ["A2A_TOKEN"])
    app = gateway.app()            # Starlette app: serve with uvicorn

Import — an A2A agent's skills as FSP capabilities:

    async with await import_agent("https://agent.example") as remote:
        agent = await franscor.connect("caller", tools=remote.capabilities)

Wire mapping
* request: one ``data`` part holds the FSP input (a ``text`` part is accepted
  and becomes ``{"text": ...}``); ``metadata["franscor.capability"]`` (or the
  skill id) selects the capability. A gateway exposing a single skill does not
  need it.
* response: a ``Message`` whose data part is the output. Failures are a
  ``Task`` in state ``REJECTED`` (authorization, approval, unknown skill) or
  ``FAILED``, its status message carrying the FSP error code.
* numbers: A2A data parts are protobuf ``Value`` (all doubles); integral values
  are converted back to integers on both sides.

Security: the gateway refuses to start without an explicit ``expose`` list,
binds where you serve it, and checks ``Authorization: Bearer <token>`` when a
token is set. Callers reached through A2A act with the *gateway's* FSP
identity, so target agents must accept the gateway's org or agent ID.
"""

from __future__ import annotations

import hmac
from contextlib import AsyncExitStack
from typing import Any, Dict, Iterable, List, Optional

from .. import errors as E
from .._version import __version__
from ..capabilities import Capability
from . import ExposeError, ImportedTools, normalize_numbers, slug

try:
    import httpx
    from a2a.client import ClientConfig, create_client
    from a2a.helpers.proto_helpers import (get_data_parts, get_text_parts, new_data_part,
                                           new_message, new_text_message, new_text_part)
    from a2a.server.agent_execution import AgentExecutor
    from a2a.server.request_handlers import DefaultRequestHandler
    from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
    from a2a.server.tasks import InMemoryTaskStore
    from a2a.types import a2a_pb2 as pb
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
except ImportError as exc:  # pragma: no cover
    raise ImportError("the A2A bridge needs `pip install franscor[a2a]`") from exc

CAPABILITY_KEY = "franscor.capability"
REJECTED_CODES = {E.DENIED, E.UNKNOWN_CAPABILITY, E.APPROVAL_REJECTED, E.OFFLINE}


# -- export ---------------------------------------------------------------------

class _Executor(AgentExecutor):
    def __init__(self, gateway: "A2AGateway"):
        self.gateway = gateway

    async def execute(self, context, event_queue) -> None:
        g = self.gateway
        message = context.message
        meta = dict(message.metadata) if message is not None else {}
        cap = meta.get(CAPABILITY_KEY) or (next(iter(g.expose)) if len(g.expose) == 1 else None)
        if not cap or cap not in g.expose:
            await event_queue.enqueue_event(_failed(context, pb.TaskState.TASK_STATE_REJECTED,
                                                    E.UNKNOWN_CAPABILITY,
                                                    f"set metadata '{CAPABILITY_KEY}' to one of the agent's skills"))
            return
        payload = _payload(message.parts if message is not None else [])
        try:
            output = await g.agent.delegate(cap, payload, timeout=g.timeout)
        except E.FSPError as exc:
            state = (pb.TaskState.TASK_STATE_REJECTED if exc.code in REJECTED_CODES
                     else pb.TaskState.TASK_STATE_FAILED)
            await event_queue.enqueue_event(_failed(context, state, exc.code, exc.message))
            return
        await event_queue.enqueue_event(new_message([new_data_part(output)],
                                                    context_id=context.context_id,
                                                    task_id=context.task_id))

    async def cancel(self, context, event_queue) -> None:
        await event_queue.enqueue_event(pb.Task(
            id=context.task_id, context_id=context.context_id,
            status=pb.TaskStatus(state=pb.TaskState.TASK_STATE_CANCELED)))


def _failed(context, state, code: str, message: str):
    return pb.Task(id=context.task_id, context_id=context.context_id,
                   status=pb.TaskStatus(state=state, message=new_text_message(
                       f"{code}: {message}", context_id=context.context_id, task_id=context.task_id)))


def _payload(parts) -> Any:
    data = get_data_parts(parts)
    if data:
        return normalize_numbers(data[0])
    text = "\n".join(get_text_parts(parts))
    return {"text": text}


class A2AGateway:
    """Serve selected FSP capabilities as an A2A agent."""

    def __init__(self, agent, expose: Iterable[str], *, base_url: str, rpc_path: str = "/a2a",
                 token: Optional[str] = None, timeout: float = 60.0,
                 description: Optional[str] = None):
        self.agent = agent
        self.expose = list(dict.fromkeys(expose))
        if not self.expose:
            raise ExposeError("expose at least one capability")
        self.base_url = base_url.rstrip("/")
        self.rpc_path = rpc_path
        self.token = token
        self.timeout = timeout
        self.description = description or f"FRANSCOR gateway for {', '.join(self.expose)}"

    async def card(self) -> "pb.AgentCard":
        known: Dict[str, Dict[str, Any]] = {}
        for card in await self.agent.discover():
            for cap in card.get("capabilities", []):
                known.setdefault(cap["name"], cap)
        skills = [pb.AgentSkill(id=name, name=name,
                                description=(known.get(name, {}).get("description") or name),
                                tags=["franscor", known.get(name, {}).get("risk", "R?")],
                                input_modes=["application/json"], output_modes=["application/json"])
                  for name in self.expose]
        return pb.AgentCard(
            name=f"franscor-{self.agent.name}", description=self.description, version=__version__,
            supported_interfaces=[pb.AgentInterface(url=self.base_url + self.rpc_path,
                                                    protocol_binding="JSONRPC", protocol_version="1.0")],
            capabilities=pb.AgentCapabilities(streaming=False),
            default_input_modes=["application/json", "text/plain"],
            default_output_modes=["application/json"], skills=skills)

    async def app(self):
        card = await self.card()
        if self.token:
            card.security_schemes["bearer"].http_auth_security_scheme.scheme = "bearer"
            card.security_requirements.add().schemes["bearer"].list.extend([])
        handler = DefaultRequestHandler(agent_executor=_Executor(self),
                                        task_store=InMemoryTaskStore(), agent_card=card)
        app = Starlette(routes=create_agent_card_routes(card) + create_jsonrpc_routes(handler, self.rpc_path))
        if not self.token:
            return app
        expected = f"Bearer {self.token}".encode("latin-1")
        rpc_path = self.rpc_path

        async def guarded(scope, receive, send):
            """ASGI wrapper: the RPC endpoint needs the bearer token; the card stays public."""
            if scope["type"] == "http" and scope["path"].rstrip("/") == rpc_path.rstrip("/"):
                given = dict(scope.get("headers") or []).get(b"authorization", b"")
                if not hmac.compare_digest(given, expected):
                    await JSONResponse({"error": "unauthorized"}, status_code=401)(scope, receive, send)
                    return
            await app(scope, receive, send)

        return guarded


# -- import -----------------------------------------------------------------------

class A2ATaskError(RuntimeError):
    """The remote A2A agent did not complete the task."""


def _decode_response(event) -> Any:
    if event.HasField("message"):
        return _payload_out(event.message.parts)
    if event.HasField("task"):
        task = event.task
        state = task.status.state
        if state == pb.TaskState.TASK_STATE_COMPLETED:
            parts = [p for a in task.artifacts for p in a.parts] or list(task.status.message.parts)
            return _payload_out(parts)
        name = pb.TaskState.Name(state).removeprefix("TASK_STATE_").lower()
        detail = "\n".join(get_text_parts(task.status.message.parts))
        raise A2ATaskError(f"remote task {name}: {detail}"[:300])
    raise A2ATaskError("unexpected A2A response")


def _payload_out(parts) -> Any:
    data = get_data_parts(parts)
    if data:
        return normalize_numbers(data[0] if len(data) == 1 else data)
    return {"text": "\n".join(get_text_parts(parts))}


async def import_agent(url: str, *, prefix: Optional[str] = None, default_risk: int = 2,
                       risk_overrides: Optional[Dict[str, int]] = None,
                       httpx_client: Optional["httpx.AsyncClient"] = None,
                       headers: Optional[Dict[str, str]] = None) -> ImportedTools:
    """Resolve an A2A agent card and wrap each skill as ``a2a.<prefix>.<skill>``."""
    stack = AsyncExitStack()
    try:
        if httpx_client is None:
            httpx_client = await stack.enter_async_context(httpx.AsyncClient(headers=headers or {},
                                                                             timeout=60))
        client = await create_client(url, client_config=ClientConfig(httpx_client=httpx_client,
                                                                     streaming=False))
        card = await client.get_card() if hasattr(client, "get_card") else None
        if card is None:
            from a2a.client import A2ACardResolver
            card = await A2ACardResolver(httpx_client, url).get_agent_card()
        prefix = slug(prefix or card.name, 40)
        caps: List[Capability] = []
        for skill in card.skills:
            caps.append(Capability(
                name=f"a2a.{prefix}.{slug(skill.id)}"[:128],
                handler=_sender(client, skill.id),
                description=(skill.description or skill.name or skill.id)[:1000],
                risk=(risk_overrides or {}).get(skill.id, default_risk),
                source="a2a", raw_input=True))
        closer = getattr(client, "close", None)
        if closer is not None:
            stack.push_async_callback(closer)
    except BaseException:
        await stack.aclose()
        raise
    return ImportedTools(caps, stack)


def _sender(client, skill_id: str):
    async def send(payload: Any = None) -> Any:
        part = new_text_part(payload) if isinstance(payload, str) else new_data_part(payload)
        msg = new_message([part], role=pb.Role.ROLE_USER)
        msg.metadata.update({CAPABILITY_KEY: skill_id})
        last = None
        async for event in client.send_message(pb.SendMessageRequest(message=msg)):
            last = event
        if last is None:
            raise A2ATaskError("no response")
        return _decode_response(last)
    return send
