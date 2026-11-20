"""`franscor` command line: hub, detect, identity, verify."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="franscor", description="FRANSCOR agent interoperability")
    sub = parser.add_subparsers(dest="cmd", required=True)

    hub = sub.add_parser("hub", help="run a local FSP hub")
    hub.add_argument("--host", default="127.0.0.1", help="bind address (default loopback only)")
    hub.add_argument("--port", type=int, default=7700)
    hub.add_argument("--identity", help="persist the hub key under this identity name")
    hub.add_argument("--revocations", type=Path,
                     help="JSONL of rotation/revocation statements (loaded and appended)")
    hub.add_argument("--rate", type=float, default=50.0, help="frames/s per session")
    hub.add_argument("--burst", type=float, default=100.0)
    hub.add_argument("--peer", action="append", default=[],
                     help="URL of a hub to federate with (repeatable)")
    hub.add_argument("--allow-peer", action="append", default=[], metavar="HUB_ID",
                     help="hub ID (fsp:...) allowed to federate, in or out (repeatable)")

    hub.add_argument("--crl", type=Path, help="passport CRL file (loaded, watched, written)")
    hub.add_argument("--operator", action="append", default=[], metavar="KEY_ID",
                     help="operator key ID (fsp:...) allowed to observe this hub from the console")
    hub.add_argument("--passport-ttl", default="24h", help="passport lifetime, e.g. 24h, 30m, 3600")
    hub.add_argument("--peering", type=Path,
                     help="peering file: partner agents need a permit (default-deny); watched")

    hub.add_argument("--audit", type=Path, metavar="DIR",
                     help="black box: audit every routing decision in a Merkle log in DIR, witnessed by peers")
    hub.add_argument("--checkpoint-interval", default="60s",
                     help="how often the audit tree is signed and sent to peers (e.g. 60s, 5m)")

    au = sub.add_parser("audit", help="inspect, export or verify a hub's black box")
    aus = au.add_subparsers(dest="au_cmd", required=True)
    aush = aus.add_parser("show", help="summary of an audit directory or an export bundle")
    aush.add_argument("path", type=Path)
    aush.add_argument("--entries", type=int, default=20, help="how many recent entries to print")
    aue = aus.add_parser("export", help="write a bundle a third party can verify (no private key needed)")
    aue.add_argument("dir", type=Path)
    aue.add_argument("--out", type=Path, required=True)
    aue.add_argument("--from", dest="start", type=int, default=0, help="first entry index")
    aue.add_argument("--to", dest="end", type=int, help="end index (exclusive); default: whole signed tree")
    aue.add_argument("--since", type=int, help="also prove consistency from this earlier tree size")
    auv = aus.add_parser("verify", help="verify an export bundle")
    auv.add_argument("bundle", type=Path)
    auv.add_argument("--hub-key", type=Path, help="the hub's public key PEM, obtained independently")
    auv.add_argument("--witness-key", type=Path, action="append", default=[],
                     help="public key PEM of a peer hub whose cosignature counts (repeatable)")
    auv.add_argument("--previous", type=Path,
                     help="an earlier bundle or checkpoint of the same hub: prove it was not rewritten")

    pm = sub.add_parser("permit", help="show, verify or revoke permits for partner agents")
    pms = pm.add_subparsers(dest="pm_cmd", required=True)
    pmsh = pms.add_parser("show", help="print a permit or a peering file in readable form")
    pmsh.add_argument("file", type=Path)
    pmv = pms.add_parser("verify", help="verify a permit offline")
    pmv.add_argument("file", type=Path)
    pmv.add_argument("--hub-key", type=Path, help="public key PEM of the hub that issued it")
    pmv.add_argument("--capability", help="also check that this capability is covered")
    pmr = pms.add_parser("revoke", help="revoke a permit in a peering file (a running hub applies it)")
    pmr.add_argument("permit", nargs="?", default="", help="permit file, or permit ID (pm_...)")
    pmr.add_argument("--peering", type=Path, required=True)
    pmr.add_argument("--agent-id", default="", help="block every permit of this agent")
    pmr.add_argument("--peer", default="", help="partner hub ID the agent belongs to")
    pmr.add_argument("--reason", default="unspecified")

    pp = sub.add_parser("passport", help="issue, show, verify or revoke agent passports")
    pps = pp.add_subparsers(dest="pp_cmd", required=True)
    ppi = pps.add_parser("issue", help="issue a passport offline with a hub key")
    ppi.add_argument("--hub", required=True, help="hub identity name (key in the key store)")
    ppi.add_argument("--agent", help="agent identity name (local key store)")
    ppi.add_argument("--agent-key", type=Path, help="agent public key PEM (instead of --agent)")
    ppi.add_argument("--org", required=True)
    ppi.add_argument("--capability", action="append", default=[])
    ppi.add_argument("--ttl", default="24h")
    ppi.add_argument("--crl", type=Path, help="refuse to issue to agents banned by this CRL")
    ppi.add_argument("--out", type=Path)
    ppsh = pps.add_parser("show", help="print a passport or a CRL in readable form")
    ppsh.add_argument("file", type=Path)
    ppv = pps.add_parser("verify", help="verify a passport offline")
    ppv.add_argument("file", type=Path)
    ppv.add_argument("--hub-key", type=Path, help="trusted hub public key PEM")
    ppv.add_argument("--crl", type=Path, help="the hub's CRL")
    ppr = pps.add_parser("revoke", help="add a passport to a hub's signed CRL")
    ppr.add_argument("passport", help="passport file, or passport ID (pp_...)")
    ppr.add_argument("--hub", required=True, help="hub identity name")
    ppr.add_argument("--crl", type=Path, required=True)
    ppr.add_argument("--agent-id", default="", help="agent ID, when giving a bare passport ID")
    ppr.add_argument("--reason", default="unspecified")
    ppr.add_argument("--no-ban", action="store_true",
                     help="revoke this passport only; the agent may get a new one")

    rev = sub.add_parser("revoke", help="print a signed revocation statement for an identity")
    rev.add_argument("name")
    rev.add_argument("--reason", default="compromised")

    sub.add_parser("detect", help="show runtime, frameworks and adapters (reads metadata only)")

    br = sub.add_parser("bridge", help="expose FSP capabilities over MCP (stdio) or A2A (HTTP)")
    br.add_argument("protocol", choices=["mcp", "a2a"])
    br.add_argument("--name", default="bridge", help="FSP identity of the bridge agent")
    br.add_argument("--hub", help="hub URL (default FRANSCOR_HUB_URL or ws://127.0.0.1:7700)")
    br.add_argument("--org", help="organization of the bridge agent")
    br.add_argument("--expose", required=True,
                    help="comma-separated capability names; '*' (MCP only) exposes all visible")
    br.add_argument("--host", default="127.0.0.1", help="A2A bind address")
    br.add_argument("--port", type=int, default=8800, help="A2A port")
    br.add_argument("--public-url", help="A2A URL advertised in the agent card")

    ident = sub.add_parser("identity", help="create or show an agent identity")
    ident.add_argument("name")

    ver = sub.add_parser("verify", help="verify an evidence log (JSONL)")
    ver.add_argument("file", type=Path)
    ver.add_argument("--key", type=Path, help="trusted public key PEM")

    args = parser.parse_args(argv)

    if args.cmd == "hub":
        from .hub import Hub
        from .identity import Identity

        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
        if args.host not in ("127.0.0.1", "localhost", "::1"):
            print(f"warning: hub exposed on {args.host}; put it behind TLS (wss://)", file=sys.stderr)
        identity = Identity.load_or_create(args.identity) if args.identity else None
        if args.peer and not args.identity:
            print("warning: federating with an ephemeral hub key; peers cannot allow-list it "
                  "across restarts (use --identity)", file=sys.stderr)
        h = Hub(args.host, args.port, identity=identity, rate=args.rate, burst=args.burst,
                revocations=args.revocations, peers=args.peer, allowed_peers=args.allow_peer,
                crl=args.crl, passport_ttl_ms=_duration_ms(args.passport_ttl),
                operators=args.operator, peering=args.peering, audit=args.audit,
                checkpoint_interval=_duration_ms(args.checkpoint_interval) / 1000)
        print(f"hub id {h.identity.agent_id} kid {h.identity.kid}")
        try:
            asyncio.run(h.serve_forever())
        except KeyboardInterrupt:
            pass
        return 0

    if args.cmd == "bridge":
        return asyncio.run(_bridge(args))

    if args.cmd == "detect":
        from .detect import detect

        print(json.dumps(detect(), indent=2))
        return 0

    if args.cmd == "identity":
        from .identity import Identity

        i = Identity.load_or_create(args.name)
        print(json.dumps({"agent_id": i.agent_id, "kid": i.kid,
                          "path": str(Identity.path_for(args.name)),
                          "public_key": i.public_pem}, indent=2))
        return 0

    if args.cmd == "passport":
        return _passport(args)

    if args.cmd == "permit":
        return _permit(args)

    if args.cmd == "audit":
        return _audit(args)

    if args.cmd == "revoke":
        from .identity import Identity
        from .keystore import default_store
        from .identity import franscor_home
        from .statements import make_revocation

        existing = default_store(franscor_home()).load(args.name)
        if not existing:
            print(f"no identity named {args.name!r}", file=sys.stderr)
            return 1
        statement = make_revocation(Identity.from_private_pem(existing), args.reason)
        print(json.dumps(statement, ensure_ascii=False))
        print("append this line to the hub's --revocations file", file=sys.stderr)
        return 0

    if args.cmd == "verify":
        from .evidence import read_log, verify_chain

        key = args.key.read_text("utf-8") if args.key else None
        report = verify_chain(read_log(args.file), key)
        print(json.dumps(report.to_dict(), indent=2))
        if not key:
            print("note: no --key given; records are checked against the key they carry "
                  "(integrity, not issuer)", file=sys.stderr)
        return 0 if report.valid else 1

    return 2


def _duration_ms(text: str) -> int:
    text = str(text).strip().lower()
    units = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}
    for suffix in ("ms", "s", "m", "h", "d"):
        if text.endswith(suffix) and text[: -len(suffix)].isdigit():
            return int(text[: -len(suffix)]) * units[suffix]
    if text.isdigit():
        return int(text) * 1000
    raise SystemExit(f"invalid duration {text!r} (examples: 24h, 30m, 3600)")


def _iso(ms: int) -> str:
    import datetime

    return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _passport(args) -> int:
    from . import errors as E
    from .identity import Identity, agent_id_from_pem, franscor_home
    from .keystore import default_store
    from .passport import crl_bans, issue_passport, revoke_in_file, verify_crl, verify_passport

    def hub_identity(name: str) -> Identity:
        pem = default_store(franscor_home()).load(name)
        if not pem:
            raise SystemExit(f"no identity named {name!r} in the key store")
        return Identity.from_private_pem(pem)

    if args.pp_cmd == "issue":
        hub = hub_identity(args.hub)
        if args.agent_key:
            agent_pem = args.agent_key.read_text("utf-8")
        elif args.agent:
            agent_pem = Identity.load_or_create(args.agent).public_pem
        else:
            raise SystemExit("give --agent or --agent-key")
        agent_id = agent_id_from_pem(agent_pem)
        if args.crl and args.crl.exists():
            crl = verify_crl(json.loads(args.crl.read_text("utf-8")), hub.public_pem)
            if crl_bans(crl, agent_id):
                print(f"refused: {agent_id} is banned by {args.crl}", file=sys.stderr)
                return 1
        doc = issue_passport(hub, agent_id=agent_id, org=args.org, agent_public_key=agent_pem,
                             capabilities=args.capability, ttl_ms=_duration_ms(args.ttl))
        text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
        if args.out:
            args.out.write_bytes(text.encode("utf-8"))
            print(f"{doc['passport_id']} -> {args.out}", file=sys.stderr)
        else:
            sys.stdout.write(text)
        return 0

    if args.pp_cmd == "show":
        doc = json.loads(args.file.read_text("utf-8"))
        if doc.get("type") == "passport-crl":
            print(f"CRL of hub {doc['hub_id']}  serial {doc['serial']}  issued {_iso(doc['issued_at'])}")
            for e in doc.get("revoked", []):
                print(f"  {e['passport_id']}  agent {e.get('agent_id') or '-'}  {_iso(e['revoked_at'])}"
                      f"  {'ban' if e.get('ban') else 'passport only'}  {e.get('reason', '')}")
            return 0
        for label, key in (("passport", "passport_id"), ("agent", "agent_id"), ("org", "org"),
                           ("issued by hub", "hub_id")):
            print(f"{label:>14}: {doc.get(key)}")
        print(f"{'capabilities':>14}: {', '.join(doc.get('capabilities', [])) or '-'}")
        print(f"{'valid from':>14}: {_iso(doc['issued_at'])}")
        print(f"{'valid until':>14}: {_iso(doc['expires_at'])}")
        return 0

    if args.pp_cmd == "verify":
        doc = json.loads(args.file.read_text("utf-8"))
        trusted = crls = None
        if args.hub_key:
            pem = args.hub_key.read_text("utf-8")
            trusted = {agent_id_from_pem(pem): pem}
            if args.crl:
                crl = verify_crl(json.loads(args.crl.read_text("utf-8")), pem)
                crls = {crl["hub_id"]: crl}
        else:
            print("note: no --hub-key; checking integrity against the key the passport carries, "
                  "not who issued it", file=sys.stderr)
        try:
            verify_passport(doc, trusted_hubs=trusted, crls=crls)
        except E.FSPError as exc:
            print(json.dumps({"valid": False, "code": exc.code, "error": exc.message}))
            return 1
        print(json.dumps({"valid": True, "passport_id": doc["passport_id"], "agent_id": doc["agent_id"],
                          "expires_at": doc["expires_at"], "revocation_checked": crls is not None}))
        return 0

    if args.pp_cmd == "revoke":
        hub = hub_identity(args.hub)
        agent_id = args.agent_id
        if Path(args.passport).is_file():
            doc = json.loads(Path(args.passport).read_text("utf-8"))
            passport_id, agent_id = doc["passport_id"], agent_id or doc["agent_id"]
        else:
            passport_id = args.passport
        crl = revoke_in_file(hub, args.crl, passport_id, agent_id=agent_id, reason=args.reason,
                             ban=not args.no_ban)
        print(f"revoked {passport_id}; CRL serial {crl['serial']} written to {args.crl} "
              "(a running hub reloads it within a second)", file=sys.stderr)
        return 0
    return 2


def _audit(args) -> int:
    from .blackbox import AuditError, open_readonly, verify_bundle

    def entry_line(leaf: str) -> str:
        e = json.loads(leaf)
        extra = "  ".join(f"{k} {e[k]}" for k in ("peer_hub_id", "passport_id", "permit_id", "code") if k in e)
        return (f"  #{e['index']:<6} {_iso(e['ts'])}  {e['decision']:<11} {e['route']:<8} {e['frame']:<12} "
                f"{e.get('from', '-')} -> {e.get('to', '-')}  {extra}")

    if args.au_cmd == "show":
        if args.path.is_dir():
            log = open_readonly(args.path)
            s = log.summary()
            cp = s["checkpoint"]
            print(f"hub {log.hub.agent_id}  entries {s['tree_size']}")
            if cp:
                print(f"last checkpoint: size {cp['tree_size']}  root {cp['root']}  {_iso(cp['ts'])}")
                print(f"cosigned by: {', '.join(s['cosigned_by']) or '-'}")
            for hub_id, size in s["witnessing"].items():
                print(f"witnessing {hub_id} up to size {size}")
            for c in s["conflicts"]:
                print(f"CONFLICT: hub {c['hub_id']} rewrote history witnessed at size {c['witnessed_size']} "
                      f"({_iso(c['detected_at'])})")
            for leaf in log.leaves[-args.entries:] if args.entries else []:
                print(entry_line(leaf))
            return 0
        bundle = json.loads(args.path.read_text("utf-8"))
        cp = bundle["checkpoint"]
        print(f"bundle of hub {bundle['hub_id']}: checkpoint size {cp['tree_size']} root {cp['root']} {_iso(cp['ts'])}")
        print(f"cosignatures: {', '.join(c['witness_id'] for c in bundle.get('cosignatures', [])) or '-'}")
        for e in bundle.get("entries", [])[-args.entries:] if args.entries else []:
            print(entry_line(e["leaf"]))
        return 0

    if args.au_cmd == "export":
        try:
            bundle = open_readonly(args.dir).export(args.start, args.end, since=args.since)
        except (AuditError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        args.out.write_bytes((json.dumps(bundle, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
        print(f"{len(bundle['entries'])} entries, checkpoint size {bundle['checkpoint']['tree_size']}, "
              f"{len(bundle['cosignatures'])} cosignature(s) -> {args.out}", file=sys.stderr)
        return 0

    if args.au_cmd == "verify":
        from .identity import agent_id_from_pem

        bundle = json.loads(args.bundle.read_text("utf-8"))
        hub_key = args.hub_key.read_text("utf-8") if args.hub_key else None
        witnesses = None
        if args.witness_key:
            witnesses = {}
            for path in args.witness_key:
                pem = path.read_text("utf-8")
                witnesses[agent_id_from_pem(pem)] = pem
        previous = None
        if args.previous:
            doc = json.loads(args.previous.read_text("utf-8"))
            previous = doc.get("checkpoint") if doc.get("type") == "audit-bundle" else doc
        if hub_key is None:
            print("note: no --hub-key; checking integrity against the key the bundle carries, "
                  "not who signed it", file=sys.stderr)
        report = verify_bundle(bundle, hub_public_key=hub_key, witness_keys=witnesses, previous=previous)
        print(json.dumps(report))
        return 0 if report["valid"] else 1
    return 2


def _permit(args) -> int:
    from . import errors as E
    from .identity import agent_id_from_pem
    from .permit import load_peering, revoke_in_file, verify_permit

    if args.pm_cmd == "show":
        doc = json.loads(args.file.read_text("utf-8"))
        if doc.get("type") == "peering":
            peering = load_peering(doc)
            for hub_id, peer in peering["peers"].items():
                print(f"peer {peer['name'] or '-'}  {hub_id}")
                for r in peer["rules"]:
                    print(f"  orgs {','.join(r['orgs'])}  agents {','.join(r['agents'])}"
                          f"  capabilities {','.join(r['capabilities'])}"
                          f"  scopes {','.join(r['scopes']) or '-'}  {r['rate_per_min']}/min"
                          f"  depth<={r['max_depth']}  ttl {r['ttl_ms'] // 1000}s"
                          f"{'  messages' if r['messages'] else ''}")
            for e in peering["revoked"]:
                print(f"revoked {e['permit_id']}  agent {e.get('agent_id') or '-'}  "
                      f"{_iso(e['revoked_at']) if e.get('revoked_at') else ''}  {e.get('reason', '')}")
            return 0
        for label, key in (("permit", "permit_id"), ("agent", "agent_id"), ("org", "org"),
                           ("passport", "passport_id"), ("partner hub", "peer_hub_id"),
                           ("issued by hub", "hub_id")):
            print(f"{label:>14}: {doc.get(key)}")
        print(f"{'capabilities':>14}: {', '.join(doc.get('capabilities', [])) or '-'}")
        print(f"{'scopes':>14}: {', '.join(doc.get('scopes', [])) or '-'}")
        print(f"{'limits':>14}: {doc.get('rate_per_min')}/min, depth <= {doc.get('max_depth')}"
              f"{', messages' if doc.get('messages') else ''}")
        print(f"{'valid from':>14}: {_iso(doc['issued_at'])}")
        print(f"{'valid until':>14}: {_iso(doc['expires_at'])}")
        return 0

    if args.pm_cmd == "verify":
        doc = json.loads(args.file.read_text("utf-8"))
        trusted = None
        if args.hub_key:
            pem = args.hub_key.read_text("utf-8")
            trusted = {agent_id_from_pem(pem): pem}
        else:
            print("note: no --hub-key; checking integrity against the key the permit carries, "
                  "not who issued it", file=sys.stderr)
        try:
            verify_permit(doc, trusted_hubs=trusted, capability=args.capability)
        except E.FSPError as exc:
            print(json.dumps({"valid": False, "code": exc.code, "error": exc.message}))
            return 1
        print(json.dumps({"valid": True, "permit_id": doc["permit_id"], "agent_id": doc["agent_id"],
                          "expires_at": doc["expires_at"]}))
        return 0

    if args.pm_cmd == "revoke":
        permit_id, agent_id, peer = args.permit, args.agent_id, args.peer
        if permit_id and Path(permit_id).is_file():
            doc = json.loads(Path(permit_id).read_text("utf-8"))
            permit_id = doc["permit_id"]
            agent_id, peer = agent_id or doc["agent_id"], peer or doc["peer_hub_id"]
        if not permit_id and not agent_id:
            raise SystemExit("give a permit (file or pm_ ID) or --agent-id")
        entry = revoke_in_file(args.peering, permit_id, agent_id=agent_id, peer_hub_id=peer,
                               reason=args.reason)
        print(f"revoked {entry['permit_id']}"
              f"{' (agent ' + entry['agent_id'] + ')' if entry.get('agent_id') else ''}; written to "
              f"{args.peering} (a running hub applies it within a second)", file=sys.stderr)
        return 0
    return 2


async def _bridge(args) -> int:
    import os

    from .client import connect

    expose = "*" if args.expose.strip() == "*" else [c.strip() for c in args.expose.split(",") if c.strip()]
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)  # stdout belongs to MCP
    agent = await connect(args.name, hub_url=args.hub, org=args.org, load_plugins=False)
    print(f"bridge agent {agent.agent_id} ({agent.org}) connected to {agent.hub_url}", file=sys.stderr)
    try:
        if args.protocol == "mcp":
            from .bridges import mcp

            await mcp.serve_stdio(mcp.build_server(agent, expose))
            return 0
        if expose == "*":
            print("A2A needs an explicit --expose list", file=sys.stderr)
            return 2
        import uvicorn

        from .bridges.a2a import A2AGateway

        token = os.environ.get("FRANSCOR_A2A_TOKEN")
        if not token:
            print("warning: FRANSCOR_A2A_TOKEN not set, the A2A endpoint accepts any caller",
                  file=sys.stderr)
        url = args.public_url or f"http://{args.host}:{args.port}"
        app = await A2AGateway(agent, expose, base_url=url, token=token).app()
        await uvicorn.Server(uvicorn.Config(app, host=args.host, port=args.port, log_level="info")).serve()
        return 0
    finally:
        await agent.close()


if __name__ == "__main__":
    sys.exit(main())
