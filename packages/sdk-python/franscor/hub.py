"""Reference FSP hub: registry, discovery, routing and federation in one process.

A modular monolith on purpose: one process, in-memory presence, no broker.
Several hubs (regions, organizations) are joined by **federation links**:
hub-to-hub WebSocket connections authenticated by hub keys on an explicit,
mutual allow-list. The hub never sees a private key and cannot forge an
agent's frame — agent IDs are derived from keys, receivers verify the
original signature, and payloads can be end-to-end encrypted.

    franscor hub                                   # 127.0.0.1:7700, ephemeral key
    franscor hub --identity eu --allow-peer fsp:… --peer wss://us.example/fsp

Federation rules (FSP 0.1 §5.1):
* a link exists only if *both* hubs allow-list each other's hub ID;
* only ``public`` agent cards are shared, one hop (no transitive re-sharing);
* revocation and rotation statements are verified and re-gossiped to every
  peer, so a stolen key is refused across the federation;
* the receiving hub re-checks signatures, visibility and accepts before
  delivering a relayed envelope.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import random
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import errors as E
from ._version import FSP_VERSION
from .envelope import AGENT_TO_AGENT, now_ms, seal, verify
from .identity import Identity, agent_id_from_pem
from .policy import card_accepts, visible_to
from .sealing import card_verified
from .statements import revoked_id, verify_statement
from .passport import DEFAULT_TTL_MS, PassportAuthority, crl_bans, verify_crl, verify_passport
from .permit import PermitOffice, request_terms
from .blackbox import AuditError, AuditLog
from .canonical import canonical_hash

log = logging.getLogger("franscor.hub")

NAME_FIELDS = ("agent_id", "name", "org", "public_key", "capabilities",
               "visibility", "accepts", "runtime")
SYNC_BATCH = 20


@dataclass
class _Bucket:
    rate: float
    burst: float
    tokens: float = 0.0
    stamp: float = field(default_factory=time.monotonic)

    def __post_init__(self):
        self.tokens = self.burst

    def take(self) -> bool:
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.stamp) * self.rate)
        self.stamp = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


@dataclass
class _Session:
    ws: Any
    card: Dict[str, Any]
    bucket: _Bucket
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    connected_at: int = field(default_factory=now_ms)
    passport: Optional[Dict[str, Any]] = None


@dataclass
class _PeerLink:
    ws: Any
    hub_id: str
    public_key: str
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    #: Tree size of our audit log this peer has witnessed (learned from peer.witnessed).
    witnessed_size: Optional[int] = None


def _valid_card(card: Any) -> bool:
    if not isinstance(card, dict) or any(f not in card for f in NAME_FIELDS):
        return False
    if card["visibility"] not in ("private", "org", "public"):
        return False
    if not isinstance(card["capabilities"], list) or len(card["capabilities"]) > 256:
        return False
    return all(isinstance(c, dict) and isinstance(c.get("name"), str) for c in card["capabilities"])


class Hub:
    def __init__(self, host: str = "127.0.0.1", port: int = 7700, *,
                 identity: Optional[Identity] = None, max_frame: int = 65536,
                 rate: float = 50.0, burst: float = 100.0,
                 revocations: "Optional[str | Path]" = None,
                 peers: Iterable[str] = (), allowed_peers: Iterable[str] = (),
                 passport_ttl_ms: int = DEFAULT_TTL_MS,
                 crl: "Optional[str | Path]" = None,
                 operators: Iterable[str] = (),
                 peering: "Optional[str | Path]" = None,
                 audit: "Optional[str | Path | bool]" = None,
                 checkpoint_interval: float = 60.0):
        self.host, self.port = host, port
        self.identity = identity or Identity.generate()
        self.max_frame = max_frame
        self.rate, self.burst = rate, burst
        self.sessions: Dict[str, _Session] = {}
        #: Test hook: set to a list to record every raw frame the hub receives.
        self.tap: Optional[list] = None
        self._server = None
        # Federation
        self.peer_urls: List[str] = list(peers)
        self.allowed_peers = set(allowed_peers)
        self.links: Dict[str, _PeerLink] = {}
        self.remote: Dict[str, Tuple[str, Dict[str, Any]]] = {}  # agent_id -> (hub_id, card)
        self._relayed: Dict[str, Tuple[str, str]] = {}            # envelope id -> (local agent, peer)
        # Remote requesters that are not public: results may flow back to them.
        self._reply_routes: "OrderedDict[str, Tuple[str, Dict[str, Any]]]" = OrderedDict()
        self._tasks: set = set()
        # Passports (FSP 0.2): this hub's office, and the CRLs of its peers.
        self.passports = PassportAuthority(self.identity, ttl_ms=passport_ttl_ms, crl_path=crl)
        self.peer_crls: Dict[str, Dict[str, Any]] = {}
        # Permits (FSP 0.2): with a peering file, federated traffic is default-deny.
        self.permits = PermitOffice(self.identity, peering)
        # Black box (FSP 0.2): every routing decision in a Merkle log; peers witness it.
        # `audit=True` keeps it in memory; a path persists it (and is checked at start).
        self.audit: Optional[AuditLog] = (
            AuditLog(self.identity, None if audit is True else audit) if audit else None)
        self.checkpoint_interval = checkpoint_interval
        # Operators: keys allowed to observe this hub (read-only console).
        self.operators = set(operators)
        self.started_at = now_ms()
        self.traffic: Dict[str, Dict[str, int]] = {"frames": {}, "routed": {}, "inbound": {}}
        # agent_id -> verified rotation/revocation statement. Persisted as JSONL
        # when `revocations` is set; every line is re-verified at load time.
        self.revoked: Dict[str, Dict[str, Any]] = {}
        self.revocations_path = Path(revocations) if revocations else None
        if self.revocations_path and self.revocations_path.exists():
            for line in self.revocations_path.read_text("utf-8").splitlines():
                if line.strip():
                    self._record_statement(json.loads(line), persist=False)

    def _record_statement(self, statement: Dict[str, Any], persist: bool = True) -> bool:
        """Verify and store; returns True if it was new."""
        verify_statement(statement)
        agent_id = revoked_id(statement)
        if agent_id in self.revoked:
            return False
        self.revoked[agent_id] = statement
        self.remote.pop(agent_id, None)
        if persist and self.revocations_path:
            self.revocations_path.parent.mkdir(parents=True, exist_ok=True)
            with self.revocations_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(statement, ensure_ascii=False) + "\n")
        return True

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> "Hub":
        from websockets.asyncio.server import serve

        # Peer frames carry relayed envelopes plus a card: allow more than an
        # agent frame; agent frames are capped individually in `_on_frame`.
        self._server = await serve(self._handle, self.host, self.port,
                                   max_size=self.max_frame * 4, ping_interval=20)
        if self.port == 0:
            self.port = next(iter(self._server.sockets)).getsockname()[1]
        log.info("FSP hub %s listening on %s:%s", self.identity.agent_id, self.host, self.port)
        if (self.allowed_peers or self.peer_urls) and not self.permits.enforcing:
            log.warning("federation without a peering file: partner agents are not bounded by permits "
                        "(FSP 0.1 behaviour); start the hub with --peering FILE to enforce them")
        self._spawn(self._watch_crl())
        if self.audit is not None:
            self._spawn(self._checkpoint_loop())
        for url in self.peer_urls:
            self._spawn(self._dial_forever(url))
        return self

    @property
    def url(self) -> str:
        return f"ws://{self.host}:{self.port}"

    async def stop(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        for link in list(self.links.values()):
            with contextlib.suppress(Exception):
                await link.ws.close()
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def serve_forever(self) -> None:
        await self.start()
        try:
            await asyncio.Future()
        finally:
            await self.stop()

    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # -- frames ------------------------------------------------------------

    def _seal(self, type_: str, body: dict, *, to: Optional[str] = None,
              corr: Optional[str] = None) -> str:
        return json.dumps(seal(self.identity, type_, body, to=to, corr=corr), ensure_ascii=False)

    async def _emit(self, session: "_Session | _PeerLink", frame: str) -> None:
        async with session.send_lock:
            await session.ws.send(frame)

    def _challenge(self, nonce: str) -> str:
        return self._seal("challenge", {
            "nonce": nonce, "hub_id": self.identity.agent_id,
            "hub_public_key": self.identity.public_pem, "fsp_versions": [FSP_VERSION]})

    async def _handle(self, ws) -> None:
        nonce = secrets.token_urlsafe(24)
        await ws.send(self._challenge(nonce))
        try:
            env = json.loads(await asyncio.wait_for(ws.recv(), 10))
            if isinstance(env, dict) and env.get("type") == "operator.hello":
                await self._accept_operator(ws, env, nonce)
                return
            if isinstance(env, dict) and env.get("type") == "peer.hello":
                await self._accept_peer(ws, env, nonce)
                return
            card = (env.get("body") or {}).get("card") if isinstance(env, dict) else None
            if env.get("type") != "register" or not _valid_card(card):
                raise E.FSPError(E.MALFORMED, "expected register with a valid card")
            verify(env, card["public_key"])
            if card["agent_id"] != env["from"] or agent_id_from_pem(card["public_key"]) != env["from"]:
                raise E.FSPError(E.ID_MISMATCH, "card does not match key")
            if not card_verified(card):
                raise E.FSPError(E.BAD_SIGNATURE, "agent card must be signed by the agent (card_sig)")
            if env["body"].get("nonce") != nonce:
                raise E.FSPError(E.BAD_NONCE, "bad nonce")
            if env["from"] in self.revoked:
                raise E.FSPError(E.REVOKED, "this key has been revoked or rotated")
            if crl_bans(self.passports.crl, env["from"]):
                raise E.FSPError(E.PASSPORT_REVOKED, "this agent's passport was revoked by this hub")
        except E.FSPError as exc:
            await ws.send(self._seal("error", exc.to_body()))
            await ws.close()
            return
        except Exception:
            await ws.close()
            return

        agent_id = env["from"]
        previous = self.sessions.get(agent_id)
        if previous is not None:
            await previous.ws.close(code=4000, reason="replaced by a new session")
        session = _Session(ws=ws, card=card, bucket=_Bucket(self.rate, self.burst))
        self.sessions[agent_id] = session
        await self._emit(session, self._seal("welcome", {
            "agent_id": agent_id, "hub_id": self.identity.agent_id,
            "session": secrets.token_hex(8), "passport": self._issue_for(session),
            **self._trust()}, to=agent_id, corr=env["id"]))
        log.info("registered %s (%s/%s)", agent_id, card["org"], card["name"])
        if card["visibility"] == "public":
            await self._broadcast("peer.update", {"added": [card], "removed": []})
        try:
            async for raw in ws:
                await self._on_frame(session, raw)
        except Exception:
            pass
        finally:
            if self.sessions.get(agent_id) is session:
                del self.sessions[agent_id]
                if card["visibility"] == "public":
                    await self._broadcast("peer.update", {"added": [], "removed": [agent_id]})
            log.info("disconnected %s", agent_id)

    async def _on_frame(self, session: _Session, raw: Any) -> None:
        me = session.card["agent_id"]
        if self.tap is not None:
            self.tap.append(raw)
        if len(raw) > self.max_frame:
            await self._emit(session, self._seal("error", {"code": E.TOO_LARGE,
                                                           "message": "frame too large"}, to=me))
            return
        if not session.bucket.take():
            await self._emit(session, self._seal("error", {"code": E.RATE_LIMITED,
                                                           "message": "rate limited"}, to=me))
            return
        try:
            env = json.loads(raw)
            verify(env, session.card["public_key"])
        except (E.FSPError, ValueError) as exc:
            body = exc.to_body() if isinstance(exc, E.FSPError) else {"code": E.MALFORMED, "message": "bad JSON"}
            await self._emit(session, self._seal("error", body, to=me))
            return

        kind = env["type"]
        self._count("frames", kind)
        if kind == "discover":
            await self._discover(session, env)
        elif kind in AGENT_TO_AGENT:
            await self._route(session, env)
        elif kind == "passport.renew":
            await self._emit(session, self._seal("passport.issued", {"passport": self._issue_for(session)},
                                                 to=me, corr=env["id"]))
        elif kind in ("identity.rotate", "identity.revoke"):
            await self._identity_statement(session, env)
        else:
            await self._emit(session, self._seal("error", {
                "code": E.MALFORMED, "message": f"{kind} is not accepted from agents"},
                to=me, corr=env["id"]))

    async def _identity_statement(self, session: _Session, env: Dict[str, Any]) -> None:
        me = session.card["agent_id"]
        statement = env["body"].get("statement")
        try:
            expected = "key-rotation" if env["type"] == "identity.rotate" else "key-revocation"
            if not isinstance(statement, dict) or statement.get("type") != expected:
                raise E.FSPError(E.MALFORMED, f"expected a {expected} statement")
            verify_statement(statement)
            if revoked_id(statement) != me:
                raise E.FSPError(E.ID_MISMATCH, "an agent can only rotate or revoke its own key")
            if self._record_statement(statement):
                await self._broadcast("peer.revoked", {"statement": statement})
        except E.FSPError as exc:
            await self._emit(session, self._seal("error", exc.to_body(), to=me, corr=env["id"]))
            return
        status = "rotated" if env["type"] == "identity.rotate" else "revoked"
        log.info("%s %s", status, me)
        await self._emit(session, self._seal("identity.ack", {"status": status, "agent_id": me},
                                             to=me, corr=env["id"]))

    async def _discover(self, session: _Session, env: Dict[str, Any]) -> None:
        body = env["body"]
        wanted, org = body.get("capability"), body.get("org")
        cards = [s.card for s in self.sessions.values()] + [c for _, c in self.remote.values()]
        found = []
        for card in cards:
            if card["agent_id"] == session.card["agent_id"] or not visible_to(card, session.card):
                continue
            if org and card["org"] != org:
                continue
            if wanted and wanted not in {c["name"] for c in card["capabilities"]}:
                continue
            found.append(card)
        await self._emit(session, self._seal("discover.result", {"agents": found[:200]},
                                             to=session.card["agent_id"], corr=env["id"]))

    def _access(self, target_card: Dict[str, Any], sender_card: Dict[str, Any], kind: str) -> str:
        if kind in ("task.request", "message") and not (
                visible_to(target_card, sender_card) and card_accepts(target_card, sender_card)):
            # "denied" only for agents the sender can already see: otherwise it
            # would reveal that a hidden agent exists.
            return "denied" if visible_to(target_card, sender_card) else "offline"
        return "delivered"

    async def _route(self, session: _Session, env: Dict[str, Any]) -> None:
        me = session.card["agent_id"]
        to = env.get("to", "")
        target = self.sessions.get(to)
        route = self.remote.get(to)
        if route is None and env["type"] == "task.result":
            route = self._reply_routes.get(to)
        peer = None
        if target is None and route is not None:
            hub_id, card = route
            peer = hub_id
            link = self.links.get(hub_id)
            status = self._access(card, session.card, env["type"]) if link else "offline"
            decision = self._decision(status, exists=link is not None)
            if status == "delivered":
                try:
                    self._relayed[env["id"]] = (me, hub_id, self._audit_fields(env))
                    await self._emit(link, self._seal("peer.relay", {"envelope": env, "sender": session.card}))
                    return  # `routed` comes back from the peer as peer.status (audited then)
                except Exception:
                    self._relayed.pop(env["id"], None)
                    status, decision = "offline", "unreachable"
        elif target is None:
            status, decision = "offline", "unreachable"
        else:
            status = self._access(target.card, session.card, env["type"])
            decision = self._decision(status, exists=True)
            if status == "delivered":
                try:
                    await self._emit(target, self._seal("deliver", {"envelope": env, "sender": session.card},
                                                        to=target.card["agent_id"]))
                except Exception:
                    status, decision = "offline", "unreachable"
        self._record("outbound" if peer else "local", self._audit_fields(env), decision,
                     code=E.DENIED if decision == "blocked" else None, peer=peer)
        self._count("routed", status)
        await self._emit(session, self._seal("routed", {"ref": env["id"], "status": status},
                                             to=me, corr=env["id"]))

    # -- federation ----------------------------------------------------------

    async def _broadcast(self, type_: str, body: dict, *, exclude: Optional[str] = None) -> None:
        frame = self._seal(type_, body)
        for hub_id, link in list(self.links.items()):
            if hub_id != exclude:
                with contextlib.suppress(Exception):
                    await self._emit(link, frame)

    def _hello(self, nonce: str) -> str:
        return self._seal("peer.hello", {"nonce": nonce, "hub": {
            "hub_id": self.identity.agent_id, "public_key": self.identity.public_pem}})

    async def _accept_peer(self, ws, env: Dict[str, Any], nonce: str) -> None:
        hub = (env.get("body") or {}).get("hub") or {}
        try:
            verify(env, str(hub.get("public_key", "")))
            if env["body"].get("nonce") != nonce:
                raise E.FSPError(E.BAD_NONCE, "bad nonce")
            if env["from"] not in self.allowed_peers:
                raise E.FSPError(E.DENIED, "hub is not an allowed peer")
        except E.FSPError as exc:
            await ws.send(self._seal("error", exc.to_body()))
            await ws.close()
            return
        await ws.send(self._seal("welcome", {"hub_id": self.identity.agent_id}, corr=env["id"]))
        await self._run_link(_PeerLink(ws=ws, hub_id=env["from"], public_key=hub["public_key"]))

    async def _dial_forever(self, url: str) -> None:
        delay = 0.5
        while True:
            try:
                await self._dial(url)
                delay = 0.5
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.info("peer %s: %s", url, exc)
            await asyncio.sleep(delay + random.uniform(0, delay / 2))
            delay = min(delay * 2, 30.0)

    async def _dial(self, url: str) -> None:
        from websockets.asyncio.client import connect as ws_connect

        async with ws_connect(url, max_size=self.max_frame * 4, open_timeout=10) as ws:
            challenge = json.loads(await asyncio.wait_for(ws.recv(), 10))
            pem = (challenge.get("body") or {}).get("hub_public_key", "")
            verify(challenge, pem)
            if challenge["from"] not in self.allowed_peers:
                raise E.FSPError(E.DENIED, f"{url} presented a hub key that is not allow-listed")
            await ws.send(self._hello(challenge["body"]["nonce"]))
            reply = json.loads(await asyncio.wait_for(ws.recv(), 10))
            verify(reply, pem)
            if reply["type"] != "welcome":
                raise E.FSPError(reply["body"].get("code", E.DENIED), reply["body"].get("message", "refused"))
            await self._run_link(_PeerLink(ws=ws, hub_id=challenge["from"], public_key=pem))

    async def _run_link(self, link: _PeerLink) -> None:
        old = self.links.get(link.hub_id)
        if old is not None:
            with contextlib.suppress(Exception):
                await old.ws.close()
        self.links[link.hub_id] = link
        log.info("federated with hub %s", link.hub_id)
        try:
            await self._sync(link)
            await self._emit(link, self._seal("peer.crl", {"crl": self.passports.crl}))
            await self._push_trust()
            if self.audit is not None:   # tell the peer how much of its history we witnessed
                seen = self.audit.witnessed.get(link.hub_id)
                await self._emit(link, self._seal("peer.witnessed", {
                    "tree_size": seen["tree_size"] if seen else 0}))
            async for raw in link.ws:
                try:
                    env = json.loads(raw)
                    verify(env, link.public_key)
                except (E.FSPError, ValueError) as exc:
                    log.warning("dropped frame from peer %s: %s", link.hub_id, exc)
                    continue
                await self._on_peer_frame(link, env)
        except Exception as exc:
            log.info("peer link %s closed: %s", link.hub_id, exc)
        finally:
            if self.links.get(link.hub_id) is link:
                del self.links[link.hub_id]
                self.peer_crls.pop(link.hub_id, None)
                with contextlib.suppress(Exception):
                    await self._push_trust()
                for agent_id in [a for a, (h, _) in self.remote.items() if h == link.hub_id]:
                    del self.remote[agent_id]

    async def _sync(self, link: _PeerLink) -> None:
        cards = [s.card for s in self.sessions.values() if s.card["visibility"] == "public"]
        statements = list(self.revoked.values())
        batches = max(1, -(-len(cards) // SYNC_BATCH), -(-len(statements) // SYNC_BATCH))
        for i in range(batches):
            await self._emit(link, self._seal("peer.sync", {
                "agents": cards[i * SYNC_BATCH:(i + 1) * SYNC_BATCH],
                "revocations": statements[i * SYNC_BATCH:(i + 1) * SYNC_BATCH]}))

    def _accept_remote_card(self, link: _PeerLink, card: Any) -> None:
        if (_valid_card(card) and card_verified(card) and card["visibility"] == "public"
                and card["agent_id"] not in self.revoked and card["agent_id"] not in self.sessions):
            self.remote[card["agent_id"]] = (link.hub_id, card)

    async def _on_peer_frame(self, link: _PeerLink, env: Dict[str, Any]) -> None:
        kind, body = env["type"], env["body"]
        if kind in ("peer.sync", "peer.update"):
            for statement in body.get("revocations", []):
                await self._peer_statement(link, statement)
            for card in body.get("agents", []) + body.get("added", []):
                self._accept_remote_card(link, card)
            for agent_id in body.get("removed", []):
                if self.remote.get(agent_id, (None,))[0] == link.hub_id:
                    del self.remote[agent_id]
        elif kind == "peer.crl":
            try:
                crl = verify_crl(body.get("crl"), link.public_key)
            except E.FSPError as exc:
                log.warning("invalid CRL from peer %s: %s", link.hub_id, exc)
                return
            if crl["serial"] >= self.peer_crls.get(link.hub_id, {}).get("serial", -1):
                self.peer_crls[link.hub_id] = crl
                await self._push_trust()
        elif kind == "peer.revoked":
            await self._peer_statement(link, body.get("statement"))
        elif kind in ("peer.witnessed", "peer.checkpoint", "peer.cosign"):
            await self._peer_audit(link, kind, body)
        elif kind == "peer.relay":
            await self._peer_relay(link, body)
        elif kind == "peer.status":
            local, peer, fields = self._relayed.pop(body.get("ref", ""), (None, None, None))
            if fields is not None and peer == link.hub_id:
                answered = body.get("status", "offline")
                self._record("outbound", fields,
                             {"delivered": "allowed", "denied": "blocked"}.get(answered, "unreachable"),
                             code=E.DENIED if answered == "denied" else None, peer=peer)
            session = self.sessions.get(local or "")
            if session is not None and peer == link.hub_id:
                await self._emit(session, self._seal("routed", {"ref": body["ref"], "status": body.get("status", "offline")},
                                                     to=local, corr=body["ref"]))

    async def _peer_statement(self, link: _PeerLink, statement: Any) -> None:
        try:
            if not self._record_statement(statement):
                return
        except E.FSPError as exc:
            log.warning("invalid statement from peer %s: %s", link.hub_id, exc)
            return
        agent_id = revoked_id(statement)
        session = self.sessions.get(agent_id)
        if session is not None:  # the revoked key is connected here: cut it off
            with contextlib.suppress(Exception):
                await session.ws.close(code=4001, reason="key revoked")
        await self._broadcast("peer.revoked", {"statement": statement}, exclude=link.hub_id)

    async def _peer_relay(self, link: _PeerLink, body: Dict[str, Any]) -> None:
        inner, sender = body.get("envelope"), body.get("sender")
        ref = inner.get("id", "") if isinstance(inner, dict) else ""
        status, decision, code, permit = "offline", "unreachable", None, None
        try:
            if not (_valid_card(sender) and card_verified(sender)):
                raise E.FSPError(E.BAD_SIGNATURE, "relayed sender card is not signed")
            verify(inner, sender["public_key"])
            if inner["from"] != sender["agent_id"] or inner["type"] not in AGENT_TO_AGENT:
                raise E.FSPError(E.ID_MISMATCH, "relayed envelope does not match its sender")
            if sender["agent_id"] in self.revoked:
                raise E.FSPError(E.REVOKED, "sender key revoked")
            target = self.sessions.get(inner.get("to", ""))
            if target is not None:
                status = self._access(target.card, sender, inner["type"])
                decision = self._decision(status, exists=True)
                if status == "delivered" and self.permits.enforcing \
                        and inner["type"] in ("task.request", "message"):
                    permit = self._admit(link, inner, sender)   # raises: refused before routing
                if status == "delivered":
                    await self._emit(target, self._seal("deliver", {
                        "envelope": inner, "sender": sender, **({"permit": permit} if permit else {})},
                        to=target.card["agent_id"]))
                    if inner["type"] == "task.request":
                        self._reply_routes[sender["agent_id"]] = (link.hub_id, sender)
                        self._reply_routes.move_to_end(sender["agent_id"])
                        while len(self._reply_routes) > 4096:
                            self._reply_routes.popitem(last=False)
        except E.FSPError as exc:
            log.warning("refused relay from %s: %s", link.hub_id, exc)
            status, decision, code = "denied", "blocked", exc.code
        except Exception:
            status, decision = "offline", "unreachable"
        if isinstance(inner, dict):
            self._record("inbound", self._audit_fields(inner), decision, code=code or (
                E.DENIED if decision == "blocked" else None), peer=link.hub_id, permit=permit)
        self._count("inbound", status)
        with contextlib.suppress(Exception):
            await self._emit(link, self._seal("peer.status", {"ref": ref, "status": status}))

    def _admit(self, link: _PeerLink, inner: Dict[str, Any], sender: Dict[str, Any]) -> Dict[str, Any]:
        """Default-deny for a partner's agent: valid passport from that partner, then a permit
        covering the action. Returns the permit; raises FSPError."""
        body = inner.get("body") or {}
        passport = body.get("passport")
        if passport is None:
            raise E.FSPError(E.PASSPORT_INVALID, "a passport is required on this federation link")
        crl = self.peer_crls.get(link.hub_id)
        verify_passport(passport, trusted_hubs={link.hub_id: link.public_key},
                        crls={link.hub_id: crl} if crl else None, agent_id=sender["agent_id"])
        permit = self.permits.permit_for(link.hub_id, passport)
        if inner["type"] == "message":
            self.permits.check(permit, capability=None, scopes=(), depth=0, message=True)
        else:
            scopes, depth = request_terms(body)
            self.permits.check(permit, capability=str(body.get("capability")), scopes=scopes, depth=depth)
        return permit

    async def revoke_permit(self, permit_id: str = "", *, agent_id: str = "", peer_hub_id: str = "",
                            reason: str = "unspecified") -> Dict[str, Any]:
        """Revoke now: the next request from that agent is refused before routing."""
        return self.permits.revoke(permit_id, agent_id=agent_id, peer_hub_id=peer_hub_id, reason=reason)

    # -- black box ---------------------------------------------------------------

    @staticmethod
    def _decision(status: str, *, exists: bool) -> str:
        if status == "delivered":
            return "allowed"
        if status == "denied":
            return "blocked"
        # "offline" for an agent that exists but may not be seen: refused, masked.
        return "masked" if exists else "unreachable"

    @staticmethod
    def _audit_fields(env: Dict[str, Any]) -> Dict[str, Any]:
        """Metadata only: the body is hashed (it is usually end-to-end encrypted)."""
        body = env.get("body") if isinstance(env.get("body"), dict) else {}
        passport = body.get("passport") if isinstance(body.get("passport"), dict) else {}
        return {"frame": env.get("type"), "envelope_id": env.get("id"), "from": env.get("from"),
                "to": env.get("to"), "payload_hash": canonical_hash(body),
                "passport_id": passport.get("passport_id") if isinstance(passport.get("passport_id"), str) else None}

    def _record(self, route: str, fields: Dict[str, Any], decision: str, *, code: Optional[str] = None,
                peer: Optional[str] = None, permit: Optional[Dict[str, Any]] = None) -> None:
        if self.audit is None:
            return
        try:
            self.audit.record(route=route, decision=decision, code=code, peer_hub_id=peer,
                              permit_id=(permit or {}).get("permit_id"), **fields)
        except Exception as exc:   # auditing must not take routing down; it is logged loudly
            log.error("audit entry not written: %s", exc)

    async def checkpoint(self) -> Optional[Dict[str, Any]]:
        """Sign the audit tree now and send it to every peer for witnessing."""
        if self.audit is None:
            return None
        cp = self.audit.checkpoint()
        for link in list(self.links.values()):
            await self._send_checkpoint(link, cp)
        return cp

    async def _send_checkpoint(self, link: _PeerLink, cp: Dict[str, Any]) -> None:
        if link.witnessed_size is None:
            return   # wait for peer.witnessed: we must prove from what the peer saw
        start = link.witnessed_size
        proof = self.audit.consistency(start, cp["tree_size"]) if start <= cp["tree_size"] else []
        with contextlib.suppress(Exception):
            await self._emit(link, self._seal("peer.checkpoint", {
                "checkpoint": cp, "from_size": start, "proof": proof}))

    async def _checkpoint_loop(self) -> None:
        while True:
            await asyncio.sleep(self.checkpoint_interval)
            try:
                await self.checkpoint()
            except Exception as exc:
                log.warning("checkpoint failed: %s", exc)

    async def _peer_audit(self, link: _PeerLink, kind: str, body: Dict[str, Any]) -> None:
        if self.audit is None:
            return
        if kind == "peer.witnessed":
            size = body.get("tree_size")
            if isinstance(size, int) and not isinstance(size, bool) and size >= 0:
                link.witnessed_size = size
                await self._send_checkpoint(link, self.audit.checkpoint())
        elif kind == "peer.checkpoint":
            try:
                cs = self.audit.witness(link.hub_id, link.public_key, body.get("checkpoint"),
                                        body.get("from_size"), body.get("proof") or [])
            except AuditError as exc:
                if "stale proof" in str(exc):   # resynchronize instead of alarming
                    seen = self.audit.witnessed.get(link.hub_id)
                    await self._emit(link, self._seal("peer.witnessed", {
                        "tree_size": seen["tree_size"] if seen else 0}))
                else:
                    log.error("AUDIT CONFLICT with hub %s: %s", link.hub_id, exc)
                return
            await self._emit(link, self._seal("peer.cosign", {"cosignature": cs}))
        elif kind == "peer.cosign":
            cs = body.get("cosignature")
            try:
                if self.audit.add_cosignature(cs, link.public_key) and isinstance(cs, dict):
                    link.witnessed_size = max(link.witnessed_size or 0, cs["tree_size"])
            except AuditError as exc:
                log.warning("invalid cosignature from %s: %s", link.hub_id, exc)

    # -- passports -------------------------------------------------------------

    def _trust(self) -> Dict[str, Any]:
        """What an agent needs to verify passports: trusted issuers and their CRLs.

        The issuers are this hub and the peers it is federated with right now;
        the agent receives them over its authenticated hub session.
        """
        issuers = {self.identity.agent_id: self.identity.public_pem}
        issuers.update({hub_id: link.public_key for hub_id, link in self.links.items()})
        crls = [self.passports.crl] + [c for h, c in self.peer_crls.items() if h in issuers]
        return {"issuers": issuers, "crls": crls}

    async def _push_trust(self) -> None:
        frame_body = self._trust()
        for agent_id, session in list(self.sessions.items()):
            with contextlib.suppress(Exception):
                await self._emit(session, self._seal("passport.trust", frame_body, to=agent_id))

    async def revoke_passport(self, passport_id: str, *, reason: str = "unspecified",
                              ban: bool = True, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Revoke now: the signed CRL goes to local agents and to every peer."""
        crl = self.passports.revoke(passport_id, agent_id=agent_id, reason=reason, ban=ban)
        await self._crl_changed()
        return crl

    async def _crl_changed(self) -> None:
        await self._broadcast("peer.crl", {"crl": self.passports.crl})
        await self._push_trust()

    async def _watch_crl(self) -> None:
        """Pick up revocations written to the CRL file by `franscor passport revoke`."""
        while True:
            await asyncio.sleep(1.0)
            try:
                if self.passports.reload():
                    log.info("CRL serial %s loaded", self.passports.crl["serial"])
                    await self._crl_changed()
            except Exception as exc:  # a bad file must not stop the hub
                log.warning("CRL file ignored: %s", exc)
            try:
                if self.permits.reload():
                    log.info("peering file reloaded: %d peer(s), %d revoked permit(s)",
                             len(self.permits.peers), len(self.permits.revoked))
            except Exception as exc:  # keep the last valid peering in force
                log.warning("peering file ignored: %s", exc)

    # -- operator console (read-only) -------------------------------------------

    def _count(self, kind: str, key: str) -> None:
        bucket = self.traffic[kind]
        bucket[key] = bucket.get(key, 0) + 1

    def _issue_for(self, session: _Session) -> Optional[Dict[str, Any]]:
        session.passport = self.passports.issue(session.card)
        return session.passport

    async def _accept_operator(self, ws, env: Dict[str, Any], nonce: str) -> None:
        """An operator console: signed hello from an allow-listed key, then read-only snapshots."""
        pem = str((env.get("body") or {}).get("public_key", ""))
        try:
            verify(env, pem)
            if env["body"].get("nonce") != nonce:
                raise E.FSPError(E.BAD_NONCE, "bad nonce")
            if env["from"] not in self.operators:
                raise E.FSPError(E.DENIED, "this key is not an operator of this hub "
                                           "(start the hub with --operator <id>)")
        except E.FSPError as exc:
            await ws.send(self._seal("error", exc.to_body()))
            await ws.close()
            return
        me = env["from"]
        await ws.send(self._seal("welcome", {"hub_id": self.identity.agent_id, "role": "operator"},
                                 to=me, corr=env["id"]))
        log.info("operator %s connected", me)
        bucket = _Bucket(5.0, 10.0)
        try:
            async for raw in ws:
                if not bucket.take() or len(raw) > 8192:
                    continue
                try:
                    req = json.loads(raw)
                    verify(req, pem)
                except (E.FSPError, ValueError):
                    continue
                if req["type"] == "hub.observe":
                    await ws.send(self._seal("hub.snapshot", self.snapshot(), to=me, corr=req["id"]))
        except Exception:
            pass

    def snapshot(self) -> Dict[str, Any]:
        """Everything a console shows. Metadata only: no payloads, no private keys."""
        def summary(card: Dict[str, Any]) -> Dict[str, Any]:
            return {"agent_id": card["agent_id"], "name": card["name"], "org": card["org"],
                    "visibility": card["visibility"],
                    "capabilities": [{"name": c["name"], "risk": c.get("risk")} for c in card["capabilities"]],
                    "runtime": {k: card.get("runtime", {}).get(k) for k in ("language", "sdk")},
                    "encryption": bool(card.get("enc_key"))}

        agents = []
        for session in self.sessions.values():
            item = summary(session.card)
            item["connected_at"] = session.connected_at
            pp = session.passport
            item["passport"] = ({"passport_id": pp["passport_id"], "expires_at": pp["expires_at"]}
                                if pp else None)
            agents.append(item)
        remote = [{**summary(card), "hub_id": hub_id} for hub_id, card in self.remote.values()]
        statements = [{"agent_id": revoked_id(st), "type": st["type"], "ts": st["ts"],
                       "reason": st.get("reason")} for st in self.revoked.values()]
        return {
            "hub_id": self.identity.agent_id, "started_at": self.started_at, "now": now_ms(),
            "agents": sorted(agents, key=lambda a: (a["org"], a["name"])),
            "remote_agents": remote,
            "federation": {
                "links": sorted(self.links), "allowed_peers": sorted(self.allowed_peers),
                "dialing": list(self.peer_urls),
                "peer_crl_serials": {h: c["serial"] for h, c in self.peer_crls.items()}},
            "permits": self.permits.summary(),
            "audit": ({**self.audit.summary(), "recent": [json.loads(t) for t in self.audit.leaves[-50:]]}
                      if self.audit is not None else {"enabled": False}),
            "passports": {"issued": len(self.passports.issued), "ttl_ms": self.passports.ttl_ms,
                          "crl_serial": self.passports.crl["serial"],
                          "revoked": self.passports.crl["revoked"]},
            "key_revocations": sorted(statements, key=lambda x: x["ts"]),
            "traffic": self.traffic,
        }
