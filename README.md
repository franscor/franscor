# FRANSCOR

**The Core of Intelligence** — a Lamstra Labs technology.

FRANSCOR connects AI agents you already have, across languages and frameworks, with a
cryptographic identity, discovery, task delegation, default-deny authorization and
signed evidence of every decision. It is not an agent framework: your business logic
stays as it is.

> Status: **0.2.0, alpha, not yet published** on PyPI or npm. Not externally audited yet:
> evaluate it before relying on it in production. See
> [ARCHITECTURE.md](ARCHITECTURE.md) for what is implemented and what is planned.

## Install (after publication)

```bash
pip install franscor        # Python ≥ 3.11
npm install franscor        # Node.js ≥ 22, zero runtime dependencies
```

Until then, from this repository:

```bash
pip install -e packages/sdk-python
cd packages/sdk-typescript && npm install && npm run build
```

## Five-minute tour

Start a local hub (binds to `127.0.0.1` only):

```bash
franscor hub
```

**Python agent** — existing functions become capabilities:

```python
import asyncio, franscor

@franscor.capability("math.stats", risk="R1")
def stats(values: list) -> dict:
    return {"count": len(values), "mean": sum(values) / len(values)}

async def main():
    agent = await franscor.connect("analyst")
    print(agent.status, agent.identity["agent_id"], agent.capabilities)
    print(await agent.delegate("text.analyze", {"text": "hello agents"}))
    await agent.wait_closed()

asyncio.run(main())
```

**TypeScript agent**:

```ts
import franscor from 'franscor';

franscor.capability('text.analyze', ({ text }: { text: string }) => ({ words: text.split(/\s+/).length }), { risk: 'R1' });

const agent = await franscor.connect({ name: 'writer' });
console.log(agent.status, agent.identity.agentId, agent.capabilities);
console.log(await agent.delegate('math.stats', { values: [1.5, 2.5, 4] }));
```

Already using LangChain or LangGraph? Pass the objects you have:

```python
agent = await franscor.connect("researcher", tools=[search_tool, compiled_graph])
# → capabilities "tool.search", "tool.<graph name>", default risk R2
```

## MCP and A2A

```bash
pip install "franscor[mcp,a2a]"

# Give any MCP host (desktop assistant, IDE) access to FSP capabilities:
franscor bridge mcp --expose math.stats,text.analyze

# Publish capabilities as an A2A agent (agent card + JSON-RPC, bearer token):
FRANSCOR_A2A_TOKEN=... franscor bridge a2a --expose math.stats --port 8800
```

```python
from franscor.bridges import mcp, a2a

async with await mcp.import_tools("http://localhost:8000/mcp") as tools,            await a2a.import_agent("https://agent.example") as remote:
    agent = await franscor.connect("hub-of-tools", tools=tools.capabilities + remote.capabilities)
```

OpenAI Agents SDK function tools (or a whole `Agent`) and AutoGen tools can be passed to
`connect(tools=[...])` directly. TypeScript: `importMcpTools(client)`.

## What happens on `connect()`

1. **Detect** the runtime and installed frameworks (package metadata only, no imports).
2. **Adapt**: built-in and plugin adapters turn your objects into capabilities.
3. **Identify**: load or create an Ed25519 key in `~/.franscor/identities/<name>.key`
   (mode 0600). The agent ID is derived from the public key.
4. **Register** with the hub through a signed challenge–response.
5. **Serve and delegate**: every frame is signed; the receiver re-verifies the sender,
   applies its own policy, asks a human for R4+ actions, runs the handler with a
   deadline, and appends a signed, chained evidence record.
6. **Stay connected**: automatic reconnection with backoff.

## Blocking code, keys, tracing

```python
# Not async? A private loop thread does the work.
with franscor.connect_sync("reporter") as agent:
    print(agent.delegate("math.stats", {"values": [1, 2, 3]}), agent.stats)

# async agent (from await franscor.connect):
await agent.rotate_key()            # new key, hub refuses the old ID from now on
await agent.revoke_key("stolen")    # permanent; or offline: franscor revoke <name>
```

* `FRANSCOR_KEY_STORE=keyring` stores keys in the OS keychain (`pip install franscor[keyring]`).
* Tracing turns on by itself when your app has OpenTelemetry configured: spans
  `franscor.delegate` and `franscor.task`, one trace across Python and TypeScript,
  no inputs or outputs recorded.

## Several hubs, end-to-end encryption

```bash
# Hub A (region EU) and hub B (region US) allow each other, B dials A:
franscor hub --identity eu --port 7701 --allow-peer <hub-us-id>
franscor hub --identity us --port 7702 --allow-peer <hub-eu-id> --peer ws://eu-host:7701
```

Public agents become discoverable and reachable from both hubs; revocations follow
everywhere. Payloads are encrypted from agent to agent, so hubs never read them
(`encryption="required"` refuses plaintext). Docker: `deploy/`.

## Passports

Each hub gives its agents a signed **passport** (agent ID, organization, key, capabilities,
validity) that anyone can verify offline with the hub's public key, plus a signed
revocation list. Agents carry it in every delegated task; run receivers with
`passport="require"` to refuse anyone without a valid one.

```bash
franscor passport issue --hub hub-eu --agent worker --org acme --capability math.add --out pp.json
franscor passport verify pp.json --hub-key hub-eu.pem --crl crl.json
franscor passport revoke pp.json --hub hub-eu --crl crl.json   # a running `franscor hub --crl crl.json` applies it
```

## Permits

A hub started with a **peering file** admits a partner hub's agents only with a **permit**:
a document it signs, bound to the agent's passport, listing what that agent may do here —
capabilities, data scopes, a rate limit, a maximum delegation depth, an expiry. Anything
else is refused before routing, and the executing agent checks the permit again
(`permit="require"` also refuses partner agents that arrive without one). Without a peering
file, federation keeps its FSP 0.1 behaviour and the hub warns at start-up.

```json
{"fsp": "0.2", "type": "peering",
 "peers": [{"hub_id": "fsp:…", "name": "globex",
            "rules": [{"orgs": ["globex"], "capabilities": ["invoice.total", "fx.*"],
                       "scopes": ["invoices:read"], "rate_per_min": 60, "max_depth": 1, "ttl": "1h"}]}]}
```

```bash
franscor hub --identity hub-eu --allow-peer fsp:… --peering peering.json
franscor permit show peering.json
franscor permit revoke pm_… --peering peering.json   # the running hub applies it within a second
```

Requesters declare scopes with `delegate(..., scopes=["invoices:read"])`; the depth of a
delegation chain is counted by the SDKs.

## Black box

With `--audit DIR`, a hub records every routing decision — allowed, blocked, masked
(refused while answering "offline") or unreachable — as an entry of an RFC 6962 Merkle
log: metadata and hashes only, never payloads. It regularly signs a checkpoint and its
federated peers check that each new tree extends the one they saw before, then cosign it.
A hub that edits its log does not start; one that rewrites and re-signs it is caught by
its peers, who keep both signed checkpoints as evidence.

```bash
franscor hub --identity hub-eu --allow-peer fsp:… --audit audit/
franscor audit export audit/ --out bundle.json            # no private key needed
franscor audit verify bundle.json --hub-key hub-eu.pem --witness-key hub-us.pem
franscor audit verify later.json --hub-key hub-eu.pem --previous bundle.json   # not rewritten since
```

Anyone can verify a bundle with the hub's public key, in Python or Node.js.

## Security defaults

| Default | Change it with |
|---|---|
| Visible only to your org | `visibility="public"` / `"private"` |
| Tasks accepted only from your org | `accept_orgs=[...]`, `accept_agents=[...]` (`"*"` = anyone, explicit) |
| R4 and R5 need human approval; no handler = refused | `approval=callback`, `approval_threshold="R3"` |
| Hub on loopback; `ws://` refused for remote hubs | `franscor hub --host …` behind TLS; `allow_insecure=True` |
| Evidence stores hashes only, never inputs or outputs | — |

Verify any evidence log, in either language, or with the InterMesh verifier:

```bash
franscor verify ~/.franscor/evidence/<agent>.jsonl --key agent.pem
```

## Layout

```
franscor/
├── protocol/            FSP 0.1 spec, JSON Schemas, cross-language test vectors
├── packages/
│   ├── sdk-python/      pip package "franscor" (SDK + reference hub + CLI)
│   └── sdk-typescript/  npm package "franscor" (SDK + CLI)
├── examples/interop/    TypeScript agent used by the acceptance test
├── tests/interop/       Python ↔ TypeScript acceptance test
└── benchmarks/          measured, not claimed
```

## Tests

```bash
cd packages/sdk-python && pytest            # unit + network
cd packages/sdk-typescript && npm test      # vectors: byte-identical to Python
cd franscor && pytest tests/interop                  # Python ↔ TypeScript acceptance
```

## Relationship to InterMesh

FRANSCOR is the successor of InterMesh. It reuses InterMesh's canonical JSON, R0–R5 risk
scale and **Action Evidence v0.1** format unchanged — evidence written by FRANSCOR verifies
with `intermesh verify`. The InterMesh hub, proxy and SDKs remain available and untouched.

License: Apache-2.0.
