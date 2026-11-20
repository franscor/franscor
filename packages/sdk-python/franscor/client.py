"""The agent runtime: `await franscor.connect()` and everything after it.

Lifecycle: detect -> load adapters -> load identity -> handshake -> serve
tasks / delegate -> reconnect on loss -> close. All network work is async;
sync capability handlers run in worker threads.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import json
import logging
import os
import random
import uuid
from collections import OrderedDict, deque
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

from . import errors as E
from ._version import FSP_VERSION, __version__
from .adapters import AdapterContext, collect, load_adapters
from .canonical import canonical_hash
from .capabilities import Approval, Capability
from .detect import detect, find_config
from .envelope import now_ms, seal, verify
from .evidence import EvidenceLog
from .identity import NAME_RE, Identity, agent_id_from_pem, franscor_home
from .policy import ALLOW, APPROVAL, AgentPolicy
from . import sealing, telemetry
from .passport import verify_crl, verify_passport
from .permit import request_terms, verify_permit
from .statements import make_revocation, make_rotation

log = logging.getLogger("franscor")

DEFAULT_HUB = "ws://127.0.0.1:7700"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
RESULT_CACHE = 1024
SEEN_IDS = 4096
# Delegation depth of the task being served (0 outside any task). A handler
# that delegates sends depth + 1, so permits can bound delegation chains.
_DEPTH: contextvars.ContextVar = contextvars.ContextVar("franscor_depth", default=0)

_BLOCK_RULES = {E.PASSPORT_EXPIRED: "passport-expired", E.PASSPORT_REVOKED: "passport-revoked",
                E.PERMIT_INVALID: "permit-invalid", E.PERMIT_EXPIRED: "permit-expired",
                E.PERMIT_REVOKED: "permit-revoked", E.PERMIT_DENIED: "permit-denied",
                E.MALFORMED: "malformed-request"}


def _load_toml(path: Optional[Path]) -> Dict[str, Any]:
    if not path:
        return {}
    import tomllib
    with path.open("rb") as handle:
        return tomllib.load(handle).get("agent", {})


def _require_secure(url: str, allow_insecure: bool) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("ws", "wss"):
        raise ValueError(f"hub URL must be ws:// or wss://, got {url!r}")
    if parts.scheme == "ws" and parts.hostname not in LOOPBACK and not allow_insecure:
        raise ValueError("refusing plain ws:// to a non-loopback hub; use wss:// "
                         "or pass allow_insecure=True explicitly")


class Agent:
    """A connected FRANSCOR agent. Create it with `franscor.connect()`."""

    def __init__(self, *, name: str, org: str, identity: Identity,
                 capabilities: Dict[str, Capability], policy: AgentPolicy,
                 visibility: str, hub_url: str, hub_kid: Optional[str],
                 evidence: EvidenceLog, adapters: list, detection: dict,
                 approval: Optional[Approval], reconnect: bool,
                 home: Optional[Path] = None, key_store=None, persist_identity: bool = False,
                 encryption: str = "auto", passport: str = "verify", permit: str = "verify"):
        self.name = name
        self.org = org
        self._identity = identity
        self._caps = capabilities
        self.policy = policy
        self.visibility = visibility
        self.hub_url = hub_url
        self._hub_kid = hub_kid
        self.evidence = evidence
        self.adapters = adapters
        self.detection = detection
        self.approval_handler = approval
        self._reconnect = reconnect
        self.status = "connecting"
        self.hub_id: Optional[str] = None
        self._ws = None
        self._reader: Optional[asyncio.Task] = None
        self._send_lock = asyncio.Lock()
        self._hub_waiters: Dict[str, asyncio.Future] = {}
        self._task_waiters: Dict[str, asyncio.Future] = {}
        self._ref_to_task: Dict[str, str] = {}
        self._results: "OrderedDict[str, dict]" = OrderedDict()
        self._running: Dict[str, asyncio.Task] = {}
        self._seen: deque = deque(maxlen=SEEN_IDS)
        self._seen_set: set = set()
        self._topic_handlers: Dict[str, Callable] = {}
        self._background: set = set()
        self._connected = asyncio.Event()
        self._home = home
        self._key_store = key_store
        self._persist_identity = persist_identity
        self.stats: Dict[str, Dict[str, int]] = {"delegated": {}, "served": {}}
        if encryption not in ("auto", "required", "off"):
            raise ValueError("encryption must be auto, required or off")
        self.encryption = encryption
        # Passports (FSP 0.2): "verify" checks a passport when one is presented,
        # "require" refuses tasks without a valid one, "off" neither sends nor checks.
        if passport not in ("verify", "require", "off"):
            raise ValueError("passport must be verify, require or off")
        self.passport_mode = passport
        # Permits (FSP 0.2): "verify" checks a permit the hub attached, "require" also
        # refuses agents of other hubs that come without one, "off" ignores permits.
        if permit not in ("verify", "require", "off"):
            raise ValueError("permit must be verify, require or off")
        self.permit_mode = permit
        self._hub_pem: Optional[str] = None
        self.passport: Optional[Dict[str, Any]] = None
        self.trusted_issuers: Dict[str, str] = {}
        self._crls: Dict[str, Dict[str, Any]] = {}
        # Verified cards of peers (signature checked), for their encryption keys.
        self._cards: "OrderedDict[str, dict]" = OrderedDict()

    # -- public view -------------------------------------------------------

    @property
    def identity(self) -> Dict[str, str]:
        return {"agent_id": self._identity.agent_id, "name": self.name, "org": self.org,
                "kid": self._identity.kid, "public_key": self._identity.public_pem}

    @property
    def agent_id(self) -> str:
        return self._identity.agent_id

    @property
    def capabilities(self) -> List[str]:
        return sorted(self._caps)

    @property
    def card(self) -> Dict[str, Any]:
        return sealing.sign_card({
            "agent_id": self._identity.agent_id, "name": self.name, "org": self.org,
            "public_key": self._identity.public_pem, "enc_key": sealing.enc_public_b64(self._identity),
            "capabilities": [c.descriptor() for c in self._caps.values()],
            "visibility": self.visibility, "accepts": self.policy.card_accepts(),
            "runtime": {"language": "python",
                        "version": self.detection["runtime"]["version"],
                        "sdk": f"franscor-python/{__version__}",
                        "adapters": [a["adapter"] for a in self.adapters if a.get("active")]},
        }, self._identity)

    def _remember(self, card: Any) -> None:
        if sealing.card_verified(card):
            self._cards[card["agent_id"]] = card
            self._cards.move_to_end(card["agent_id"])
            while len(self._cards) > SEEN_IDS:
                self._cards.popitem(last=False)

    async def _enc_key_for(self, agent_id: str) -> Optional[str]:
        if self.encryption == "off":
            return None
        if agent_id not in self._cards:
            with contextlib.suppress(Exception):
                await self.discover()
        key = sealing.enc_key_of(self._cards.get(agent_id))
        if key is None and self.encryption == "required":
            raise E.TaskError("rejected", E.ENCRYPTION_REQUIRED,
                              "recipient has no verified encryption key")
        return key

    def __repr__(self) -> str:
        return f"<franscor.Agent {self.name} {self.agent_id} {self.status}>"

    # -- connection --------------------------------------------------------

    async def _open(self) -> None:
        from websockets.asyncio.client import connect as ws_connect

        ws = await ws_connect(self.hub_url, max_size=1 << 20, open_timeout=10)
        try:
            challenge = json.loads(await asyncio.wait_for(ws.recv(), 10))
            hub_pem = (challenge.get("body") or {}).get("hub_public_key", "")
            verify(challenge, hub_pem)
            if challenge["type"] != "challenge":
                raise E.FSPError(E.MALFORMED, "expected challenge")
            if self._hub_kid and challenge["sig"]["kid"] != self._hub_kid:
                raise E.FSPError(E.BAD_SIGNATURE, "hub key does not match the pinned FRANSCOR_HUB_KID")
            if FSP_VERSION not in challenge["body"].get("fsp_versions", []):
                raise E.FSPError(E.UNSUPPORTED_VERSION, "hub does not speak FSP 0.1")
            register = seal(self._identity, "register",
                            {"nonce": challenge["body"]["nonce"], "card": self.card})
            await ws.send(json.dumps(register))
            reply = json.loads(await asyncio.wait_for(ws.recv(), 10))
            verify(reply, hub_pem)
            if reply["type"] == "error":
                raise E.FSPError(reply["body"].get("code", E.MALFORMED), reply["body"].get("message", ""))
            if reply["type"] != "welcome":
                raise E.FSPError(E.MALFORMED, "expected welcome")
        except BaseException:
            await ws.close()
            raise
        self._ws = ws
        self._hub_pem = hub_pem
        self.hub_id = challenge["from"]
        self.passport = reply["body"].get("passport")
        self._apply_trust(reply["body"])
        self.status = "connected"
        self._connected.set()
        self._reader = asyncio.create_task(self._read_loop(ws))

    async def _read_loop(self, ws) -> None:
        try:
            async for raw in ws:
                try:
                    frame = json.loads(raw)
                    verify(frame, self._hub_pem)
                except (E.FSPError, ValueError) as exc:
                    log.warning("dropped frame from hub: %s", exc)
                    continue
                self._spawn(self._dispatch(frame))
        except Exception as exc:  # connection loss
            log.info("connection lost: %s", exc)
        finally:
            self._connected.clear()
            for fut in self._hub_waiters.values():
                if not fut.done():
                    fut.set_exception(ConnectionError("connection to hub lost"))
            self._hub_waiters.clear()
            if self.status != "closed":
                if self._reconnect:
                    self.status = "reconnecting"
                    self._spawn(self._reconnect_loop())
                else:
                    self.status = "disconnected"

    async def _reconnect_loop(self) -> None:
        delay = 0.5
        while self.status == "reconnecting":
            await asyncio.sleep(delay + random.uniform(0, delay / 2))
            try:
                await self._open()
                log.info("reconnected to %s", self.hub_url)
                return
            except Exception as exc:
                log.info("reconnect failed: %s", exc)
                delay = min(delay * 2, 10.0)

    def _spawn(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self._background.add(task)
        task.add_done_callback(self._background.discard)
        return task

    async def _send(self, env: Dict[str, Any]) -> None:
        if not self._connected.is_set():
            await asyncio.wait_for(self._connected.wait(), 10)
        async with self._send_lock:
            await self._ws.send(json.dumps(env, ensure_ascii=False))

    async def close(self) -> None:
        self.status = "closed"
        for task in list(self._running.values()):
            task.cancel()
        if self._ws is not None:
            await self._ws.close()
        if self._reader:
            with contextlib.suppress(Exception):
                await self._reader
        for task in list(self._background):
            task.cancel()

    async def __aenter__(self) -> "Agent":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def wait_closed(self) -> None:
        """Serve until `close()` (or Ctrl-C)."""
        while self.status != "closed":
            await asyncio.sleep(0.5)

    # -- hub requests ------------------------------------------------------

    async def _hub_request(self, type_: str, body: dict, timeout: float) -> Dict[str, Any]:
        env = seal(self._identity, type_, body)
        fut = asyncio.get_running_loop().create_future()
        self._hub_waiters[env["id"]] = fut
        try:
            await self._send(env)
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._hub_waiters.pop(env["id"], None)

    async def discover(self, capability: Optional[str] = None, *, org: Optional[str] = None,
                       timeout: float = 5.0) -> List[Dict[str, Any]]:
        body: Dict[str, Any] = {}
        if capability:
            body["capability"] = capability
        if org:
            body["org"] = org
        reply = await self._hub_request("discover", body, timeout)
        agents = [a for a in reply["body"].get("agents", [])
                  if isinstance(a, dict) and sealing.card_verified(a)]
        for card in agents:
            self._remember(card)
        return agents

    # -- messaging ---------------------------------------------------------

    def on_message(self, topic: str):
        def wrap(fn):
            self._topic_handlers[topic] = fn
            return fn
        return wrap

    async def send(self, to: str, topic: str, data: Any = None) -> None:
        body: Dict[str, Any] = {"topic": topic}
        key = await self._enc_key_for(to)
        if key:
            body["sealed"] = sealing.seal(data, key, sealing.aad("message", self.agent_id, to, f"message:{topic}"))
        else:
            body["data"] = data
        passport = await self._current_passport()
        if passport:
            body["passport"] = passport
        await self._send(seal(self._identity, "message", body, to=to))

    # -- delegation (requester side) --------------------------------------

    async def delegate(self, capability: str, input: Any = None, *, to: Optional[str] = None,
                       timeout: float = 30.0, retries: int = 1,
                       scopes: Optional[List[str]] = None) -> Any:
        """Run `capability` on another agent and return its output.

        Picks the first visible agent offering the capability unless `to` is
        given. `timeout` applies per attempt; retries reuse the same task_id,
        so the receiver executes once.
        `scopes` declares the data scopes the task needs; across a federation
        link with permits, each must be allowed by the permit.
        Raises `TaskError` on any non-completed outcome.
        """
        if to is None:
            candidates = [a for a in await self.discover(capability)
                          if a["agent_id"] != self.agent_id]
            if not candidates:
                raise E.TaskError("rejected", E.OFFLINE, f"no reachable agent offers {capability!r}")
            to = candidates[0]["agent_id"]
        task_id = str(uuid.uuid4())
        attrs = {"franscor.capability": capability, "franscor.task_id": task_id, "franscor.peer": to}
        status = "failed"
        with telemetry.client_span("franscor.delegate", attrs) as (span, carrier):
            try:
                output = await self._delegate(capability, input, to, task_id, timeout, retries, carrier,
                                              list(scopes or []))
                status = "completed"
                return output
            except E.TaskError as exc:
                status = exc.status
                span.fail(exc.code)
                raise
            finally:
                span.set_attribute("franscor.status", status)
                self._count("delegated", status)

    def _count(self, kind: str, status: str) -> None:
        bucket = self.stats[kind]
        bucket[status] = bucket.get(status, 0) + 1

    async def _delegate(self, capability: str, input: Any, to: str, task_id: str,
                        timeout: float, retries: int, carrier: Optional[dict],
                        scopes: Optional[List[str]] = None) -> Any:
        # Receiver budget covers every attempt, so a slow first run is not killed
        # before a retry can collect its (cached) result.
        deadline_ms = min(3_600_000, max(1, int(timeout * 1000 * (retries + 1))))
        key = await self._enc_key_for(to)
        passport = await self._current_passport()
        depth = _DEPTH.get()
        payload: Dict[str, Any] = (
            {"sealed": sealing.seal(input, key, sealing.aad("task.request", self.agent_id, to, task_id))}
            if key else {"input": input})
        fut = asyncio.get_running_loop().create_future()
        self._task_waiters[task_id] = fut
        try:
            for attempt in range(retries + 1):
                env = seal(self._identity, "task.request",
                           {"task_id": task_id, "capability": capability,
                            **payload, "deadline_ms": deadline_ms,
                            **({"passport": passport} if passport else {}),
                            **({"scopes": scopes} if scopes else {}),
                            **({"depth": depth} if depth else {}),
                            **({"trace": carrier} if carrier else {})}, to=to)
                self._ref_to_task[env["id"]] = task_id
                await self._send(env)
                try:
                    body = await asyncio.wait_for(asyncio.shield(fut), timeout)
                    break
                except asyncio.TimeoutError:
                    if attempt == retries:
                        with contextlib.suppress(Exception):
                            await self._send(seal(self._identity, "task.cancel",
                                                  {"task_id": task_id}, to=to))
                        raise E.TaskError("timeout", E.TIMEOUT,
                                          f"no result after {timeout}s", task_id) from None
        finally:
            self._task_waiters.pop(task_id, None)
        if body.get("status") == "completed":
            if "sealed" in body:
                try:
                    return sealing.open_sealed(body["sealed"], self._identity,
                                               sealing.aad("task.result", to, self.agent_id, task_id))
                except E.FSPError as exc:
                    raise E.TaskError("failed", exc.code, exc.message, task_id) from None
            if key:
                raise E.TaskError("failed", E.ENCRYPTION_REQUIRED, "result was not encrypted", task_id)
            return body.get("output")
        err = body.get("error") or {}
        raise E.TaskError(body.get("status", "failed"), err.get("code", E.HANDLER_FAILED),
                          err.get("message", "task failed"), task_id)

    # -- dispatch ----------------------------------------------------------

    async def _dispatch(self, frame: Dict[str, Any]) -> None:
        kind = frame["type"]
        if kind == "passport.trust":
            self._apply_trust(frame["body"])
            return
        if kind in ("discover.result", "identity.ack", "passport.issued", "error") and frame.get("corr") in self._hub_waiters:
            fut = self._hub_waiters[frame["corr"]]
            if kind == "error":
                body = frame["body"]
                fut.set_exception(E.FSPError(body.get("code", E.MALFORMED), body.get("message", "")))
            else:
                fut.set_result(frame)
            return
        if kind == "routed":
            body = frame["body"]
            task_id = self._ref_to_task.pop(body.get("ref", ""), None)
            if task_id and body.get("status") in ("offline", "denied"):
                fut = self._task_waiters.get(task_id)
                if fut and not fut.done():
                    code = E.OFFLINE if body["status"] == "offline" else E.DENIED
                    fut.set_result({"task_id": task_id, "status": "rejected",
                                    "error": {"code": code, "message": f"recipient {body['status']}"}})
            return
        if kind != "deliver":
            return
        inner, sender = frame["body"].get("envelope"), frame["body"].get("sender")
        try:
            if not isinstance(sender, dict):
                raise E.FSPError(E.MALFORMED, "deliver without sender card")
            verify(inner, sender.get("public_key", ""))
            if sender.get("agent_id") != inner["from"] or inner.get("to") != self.agent_id:
                raise E.FSPError(E.ID_MISMATCH, "sender card or recipient mismatch")
        except (E.FSPError, ValueError) as exc:
            log.warning("rejected delivered envelope: %s", exc)
            return
        if inner["id"] in self._seen_set:
            return
        if len(self._seen) == self._seen.maxlen:
            self._seen_set.discard(self._seen[0])
        self._seen.append(inner["id"])
        self._seen_set.add(inner["id"])

        self._remember(sender)
        kind = inner["type"]
        if kind == "task.request":
            await self._serve_task(inner, sender, frame["body"].get("permit"))
        elif kind == "task.result":
            body = inner["body"]
            fut = self._task_waiters.get(body.get("task_id", ""))
            if fut and not fut.done():
                fut.set_result(body)
        elif kind == "task.cancel":
            key = f"{inner['from']}:{inner['body'].get('task_id')}"
            task = self._running.get(key)
            if task:
                task.cancel()
        elif kind == "message":
            topic = inner["body"].get("topic", "")
            handler = self._topic_handlers.get(topic)
            if handler:
                data = inner["body"].get("data")
                if "sealed" in inner["body"]:
                    try:
                        data = sealing.open_sealed(inner["body"]["sealed"], self._identity,
                                                   sealing.aad("message", inner["from"], self.agent_id,
                                                               f"message:{topic}"))
                    except E.FSPError as exc:
                        log.warning("dropped message: %s", exc)
                        return
                result = handler(data, sender)
                if asyncio.iscoroutine(result):
                    await result

    # -- delegation (receiver side) ---------------------------------------

    async def _serve_task(self, env: Dict[str, Any], sender: Dict[str, Any],
                          permit: Optional[Dict[str, Any]] = None) -> None:
        body = env["body"]
        attrs = {"franscor.capability": str(body.get("capability")),
                 "franscor.task_id": str(body.get("task_id")), "franscor.peer": env["from"]}
        with telemetry.server_span("franscor.task", attrs, body.get("trace")) as span:
            result = await self._serve_task_inner(env, sender, permit)
            if result is not None:
                span.set_attribute("franscor.status", result["status"])
                if result["status"] != "completed":
                    span.fail(result.get("error", {}).get("code", ""))
                self._count("served", result["status"])

    async def _serve_task_inner(self, env: Dict[str, Any], sender: Dict[str, Any],
                                permit: Optional[Dict[str, Any]] = None) -> Optional[dict]:
        body = env["body"]
        task_id, cap_name = body.get("task_id"), body.get("capability")
        deadline = body.get("deadline_ms")
        if not (isinstance(task_id, str) and isinstance(cap_name, str)
                and isinstance(deadline, int) and 0 < deadline <= 3_600_000):
            return None
        key = f"{env['from']}:{task_id}"
        if key in self._results:
            await self._reply(env, self._results[key])
            return None
        if key in self._running:
            return None
        cap = self._caps.get(cap_name)
        passport_id, block_code, attested = None, None, sender
        presented = body.get("passport")
        if self.passport_mode != "off" and presented is not None:
            try:
                verify_passport(presented, trusted_hubs=self.trusted_issuers, crls=self._crls,
                                agent_id=env["from"])
                passport_id = presented["passport_id"]
                # The hub-attested organization replaces the self-declared one.
                attested = {**sender, "org": presented["org"]}
            except E.FSPError as exc:
                block_code = exc.code
        elif self.passport_mode == "require":
            block_code = E.PASSPORT_INVALID
        block_rule = None
        permit_id, depth = None, 0
        if block_code is None and self.passport_mode != "off" and self.permit_mode != "off":
            try:
                scopes, depth = request_terms(body)
                if permit is not None:
                    if passport_id is None:
                        raise E.FSPError(E.PERMIT_INVALID, "a permit needs the passport it is bound to")
                    # Only our own hub issues the permits we honour.
                    verify_permit(permit, trusted_hubs={self.hub_id: self._hub_pem} if self._hub_pem else {},
                                  agent_id=env["from"], passport=presented, capability=cap_name,
                                  scopes=scopes, depth=depth)
                    permit_id = permit["permit_id"]
                elif self.permit_mode == "require" and (passport_id is None or presented["hub_id"] != self.hub_id):
                    block_rule = "permit-required"
                    raise E.FSPError(E.PERMIT_INVALID, "agents of other hubs need a permit")
            except E.FSPError as exc:
                block_code = exc.code
        decision, rule = self.policy.decide(attested, cap)
        if block_code is not None:
            decision, rule = "block", block_rule or _BLOCK_RULES.get(
                block_code, "passport-invalid" if presented is not None else "passport-required")
        task_input = body.get("input")
        if "sealed" in body:
            try:
                task_input = sealing.open_sealed(body["sealed"], self._identity,
                                                 sealing.aad("task.request", env["from"], self.agent_id, task_id))
            except E.FSPError:
                decision, rule, task_input = "block", "undecryptable-payload", None
        elif self.encryption == "required" and block_code is None:
            decision, rule = "block", "plaintext-refused"
        input_hash = canonical_hash(task_input)
        common = dict(agent_id=self.agent_id, org=self.org, capability=cap_name,
                      risk=cap.risk if cap else 0, task_id=task_id,
                      requester=env["from"], input_hash=input_hash, passport_id=passport_id,
                      permit_id=permit_id)

        if decision not in (ALLOW, APPROVAL):
            code = (block_code if block_code is not None else
                    E.UNKNOWN_CAPABILITY if cap is None else
                    E.BAD_SIGNATURE if rule == "undecryptable-payload" else
                    E.ENCRYPTION_REQUIRED if rule == "plaintext-refused" else E.DENIED)
            rec = self.evidence.append(decision="block", rule=rule, status="blocked", **common)
            return await self._finish(env, key, {"task_id": task_id, "status": "rejected",
                                                 "error": {"code": code, "message": rule},
                                                 "evidence_hash": rec["evidence"]["hash"]})

        if decision == APPROVAL:
            approved = False
            if self.approval_handler is not None:
                info = {"task_id": task_id, "capability": cap_name, "risk": f"R{cap.risk}",
                        "input": task_input,
                        "requester": {k: sender.get(k) for k in ("agent_id", "name", "org")}}
                try:
                    verdict = self.approval_handler(info)
                    approved = bool(await verdict if asyncio.iscoroutine(verdict) else verdict)
                except Exception as exc:
                    log.warning("approval handler failed: %s", exc)
            if not approved:
                rec = self.evidence.append(decision="approval", rule=rule,
                                           status="approval_rejected", **common)
                return await self._finish(env, key, {
                    "task_id": task_id, "status": "approval_rejected",
                    "error": {"code": E.APPROVAL_REJECTED,
                              "message": "human approval required and not granted"},
                    "evidence_hash": rec["evidence"]["hash"]})

        token = _DEPTH.set(depth + 1)   # copied into the handler's task
        try:
            run = asyncio.create_task(cap.invoke(task_input))
        finally:
            _DEPTH.reset(token)
        self._running[key] = run
        try:
            output = await asyncio.wait_for(run, deadline / 1000)
            canonical_hash(output)  # output must be portable JSON
            rec = self.evidence.append(decision=decision, rule=rule, status="executed",
                                       response_hash=canonical_hash(output), **common)
            result = {"task_id": task_id, "status": "completed", "output": output,
                      "evidence_hash": rec["evidence"]["hash"]}
        except asyncio.TimeoutError:
            rec = self.evidence.append(decision=decision, rule=rule, status="failed", **common)
            result = {"task_id": task_id, "status": "timeout",
                      "error": {"code": E.TIMEOUT, "message": "deadline exceeded"},
                      "evidence_hash": rec["evidence"]["hash"]}
        except asyncio.CancelledError:
            if self.status == "closed":
                raise
            rec = self.evidence.append(decision=decision, rule=rule, status="failed", **common)
            result = {"task_id": task_id, "status": "cancelled",
                      "error": {"code": E.HANDLER_FAILED, "message": "cancelled by requester"},
                      "evidence_hash": rec["evidence"]["hash"]}
        except Exception as exc:
            rec = self.evidence.append(decision=decision, rule=rule, status="failed", **common)
            # The exception type only: messages can carry sensitive data.
            result = {"task_id": task_id, "status": "failed",
                      "error": {"code": E.HANDLER_FAILED, "message": type(exc).__name__},
                      "evidence_hash": rec["evidence"]["hash"]}
        finally:
            self._running.pop(key, None)
        return await self._finish(env, key, result)

    async def _finish(self, env: Dict[str, Any], key: str, result: Dict[str, Any]) -> Dict[str, Any]:
        self._results[key] = result
        while len(self._results) > RESULT_CACHE:
            self._results.popitem(last=False)
        await self._reply(env, result)
        return result

    async def _reply(self, env: Dict[str, Any], result: Dict[str, Any]) -> None:
        if "output" in result and "sealed" in env["body"]:
            # Encrypted request -> encrypted result, to the requester's verified key.
            key = sealing.enc_key_of(self._cards.get(env["from"]))
            output = result["output"]
            result = {k: v for k, v in result.items() if k != "output"}
            if key:
                result["sealed"] = sealing.seal(
                    output, key, sealing.aad("task.result", self.agent_id, env["from"], result["task_id"]))
            else:
                result = {**result, "status": "failed",
                          "error": {"code": E.ENCRYPTION_REQUIRED, "message": "no key to encrypt the result"}}
        try:
            await self._send(seal(self._identity, "task.result", result,
                                  to=env["from"], corr=env["id"]))
        except Exception as exc:
            log.warning("could not send task result: %s", exc)

    # -- passports ----------------------------------------------------------

    def _apply_trust(self, body: Dict[str, Any]) -> None:
        """Trusted passport issuers and their CRLs, as announced by our hub."""
        issuers = body.get("issuers")
        if isinstance(issuers, dict):
            clean = {}
            for hub_id, pem in issuers.items():
                with contextlib.suppress(Exception):
                    if agent_id_from_pem(pem) == hub_id:
                        clean[hub_id] = pem
            self.trusted_issuers = clean
            self._crls = {h: c for h, c in self._crls.items() if h in clean}
        for crl in body.get("crls") or []:
            pem = self.trusted_issuers.get(crl.get("hub_id", "")) if isinstance(crl, dict) else None
            if pem is None:
                continue
            with contextlib.suppress(E.FSPError):
                verify_crl(crl, pem)
                if crl["serial"] >= self._crls.get(crl["hub_id"], {}).get("serial", -1):
                    self._crls[crl["hub_id"]] = crl

    async def _current_passport(self) -> Optional[Dict[str, Any]]:
        """Our passport, renewed when less than 10 % (min 5 s) of its life remains."""
        if self.passport_mode == "off" or self.passport is None:
            return None
        p = self.passport
        margin = max(5_000, (p["expires_at"] - p["issued_at"]) // 10)
        if p["expires_at"] - now_ms() < margin:
            with contextlib.suppress(Exception):
                reply = await self._hub_request("passport.renew", {}, 5.0)
                if reply["body"].get("passport"):
                    self.passport = reply["body"]["passport"]
        return self.passport

    # -- identity lifecycle -----------------------------------------------

    async def rotate_key(self, *, timeout: float = 10.0) -> Dict[str, Any]:
        """Replace this agent's key. Returns the signed rotation statement.

        The hub records the old ID as rotated (it can no longer register),
        the new key is persisted (the old key is kept as
        ``<name>.key.rotated-<ms>``), and the agent reconnects under its new ID.
        Peers that allow-listed the old ID must update ``accept_agents``.
        """
        old, new = self._identity, Identity.generate()
        statement = make_rotation(old, new)
        reply = await self._hub_request("identity.rotate", {"statement": statement}, timeout)
        if reply["body"].get("status") != "rotated":
            raise E.FSPError(E.MALFORMED, "hub did not confirm the rotation")
        if self._persist_identity:
            new.save(self.name, self._key_store, replace=True)
        self._identity = new
        if self._home is not None:
            self.evidence = EvidenceLog(self._home / "evidence" / f"{new.agent_id[4:]}.jsonl",
                                        new, self.org)
        reconnect, self._reconnect = self._reconnect, False
        await self._ws.close()
        if self._reader:
            with contextlib.suppress(Exception):
                await self._reader
        self._reconnect = reconnect
        self.status = "connecting"
        await self._open()
        return statement

    async def revoke_key(self, reason: str = "unspecified", *, timeout: float = 10.0) -> Dict[str, Any]:
        """Permanently take this agent's key out of service on the hub, then close."""
        statement = make_revocation(self._identity, reason)
        reply = await self._hub_request("identity.revoke", {"statement": statement}, timeout)
        if reply["body"].get("status") != "revoked":
            raise E.FSPError(E.MALFORMED, "hub did not confirm the revocation")
        await self.close()
        return statement


async def connect(name: Optional[str] = None, *, hub_url: Optional[str] = None,
                  org: Optional[str] = None, tools: Optional[list] = None,
                  visibility: Optional[str] = None,
                  accept_orgs: Optional[List[str]] = None,
                  accept_agents: Optional[List[str]] = None,
                  approval_threshold: "str | int" = "R4",
                  approval: Optional[Approval] = None,
                  identity: Optional[Identity] = None,
                  home: Optional[Path] = None,
                  load_plugins: bool = True, reconnect: bool = True,
                  allow_insecure: bool = False, adapters: Optional[list] = None,
                  key_store=None, encryption: str = "auto", passport: Optional[str] = None,
                  permit: Optional[str] = None) -> Agent:
    """Detect, adapt, identify, register and connect — in that order.

    Configuration precedence: arguments > environment (FRANSCOR_*) >
    `franscor.toml` [agent] section > defaults. Nothing is exposed beyond
    your org unless you set `visibility="public"` and widen `accept_orgs`.
    """
    from .capabilities import parse_risk

    detection = detect()
    cfg = _load_toml(find_config())
    env = os.environ
    name = name or env.get("FRANSCOR_NAME") or cfg.get("name") or Path.cwd().name.lower()
    name = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in name.lower())[:64]
    if not NAME_RE.match(name):
        raise ValueError(f"invalid agent name {name!r}")
    org = org or env.get("FRANSCOR_ORG") or cfg.get("org") or "local"
    hub_url = hub_url or env.get("FRANSCOR_HUB_URL") or cfg.get("hub_url") or DEFAULT_HUB
    visibility = visibility or env.get("FRANSCOR_VISIBILITY") or cfg.get("visibility") or "org"
    if visibility not in ("private", "org", "public"):
        raise ValueError("visibility must be private, org or public")
    _require_secure(hub_url, allow_insecure)
    home = Path(home) if home else franscor_home()

    loaded, load_errors = (adapters, []) if adapters is not None else load_adapters(load_plugins)
    caps, report = collect(AdapterContext(objects=list(tools or []), detection=detection), loaded)
    report.extend(load_errors)

    from .keystore import default_store

    store = key_store or default_store(home)
    ident = identity or Identity.load_or_create(name, home, store)
    policy = AgentPolicy(org=org,
                         accept_orgs=list(accept_orgs or cfg.get("accept_orgs") or []),
                         accept_agents=list(accept_agents or cfg.get("accept_agents") or []),
                         approval_threshold=parse_risk(cfg.get("approval_threshold", approval_threshold)))
    evidence = EvidenceLog(home / "evidence" / f"{ident.agent_id[4:]}.jsonl", ident, org)
    agent = Agent(name=name, org=org, identity=ident, capabilities=caps, policy=policy,
                  visibility=visibility, hub_url=hub_url,
                  hub_kid=env.get("FRANSCOR_HUB_KID"), evidence=evidence, adapters=report,
                  detection=detection, approval=approval, reconnect=reconnect,
                  home=home, key_store=store, persist_identity=identity is None,
                  encryption=os.environ.get("FRANSCOR_ENCRYPTION", encryption),
                  passport=passport or os.environ.get("FRANSCOR_PASSPORT", "verify"),
                  permit=permit or os.environ.get("FRANSCOR_PERMIT", "verify"))
    await agent._open()
    return agent
