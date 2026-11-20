# FSP 0.1 — FRANSCOR Protocol

Status: **draft, implemented by `franscor` 0.1.0 (Python and TypeScript)**.
Every statement in this document is enforced by code in `packages/` and
checked by the shared test vectors in `protocol/vectors/`. A requirement
that is not yet implemented is marked **(planned)**.

FSP is a thin, language-independent layer for agent identity, discovery,
messaging, task delegation and signed evidence. It deliberately does not
replace MCP (tool access for one model) or A2A (agent task exchange over
HTTP): bridges to both are planned adapters. What FSP adds is a
self-certifying identity, a signature on every frame, a default-deny
authorization model and a verifiable evidence chain.

## 1. Encoding

* Transport: WebSocket, one JSON object per text frame. Max frame size
  64 KiB by default (hub-configurable).
* **Canonical form** (used for every hash and signature): UTF-8 JSON, object
  keys sorted by Unicode code point, separators `,` and `:` without spaces,
  non-ASCII characters left unescaped, no `undefined`.
* **Numbers**: non-integral numbers are serialized like ECMAScript
  `Number.prototype.toString` (the RFC 8785 rule), so Python and JavaScript
  agree byte for byte. Integral values beyond 2^53−1 (int or float), NaN and
  infinities MUST be rejected: send them as strings. Protocol fields
  (`ts`, `deadline_ms`, evidence) are always integers; evidence records
  contain no floats at all, which keeps them byte-compatible with InterMesh.
* Conformance is defined by `protocol/vectors/vectors.json`: a seeded key,
  canonical cases, one envelope and one evidence record. Ed25519 is
  deterministic, so an implementation must reproduce those bytes exactly.
* `b64` means base64url without padding.

## 2. Identity

An agent identity is an Ed25519 key pair. The private key never leaves the
agent's machine (default store: `$FRANSCOR_HOME/identities/<name>.key`,
`FRANSCOR_HOME` defaults to `~/.franscor`).

```
agent_id = "fsp:" + hex(sha256(raw_public_key_32_bytes))[0:32]
kid      = hex(sha256(public_key_pem_utf8))[0:16]
```

The agent ID is **self-certifying**: anyone holding the public key can
recompute it. A hub therefore cannot substitute a key for an agent without
changing the agent's ID.

`public_key` is the SubjectPublicKeyInfo PEM, exactly as produced by
OpenSSL/Node (`-----BEGIN PUBLIC KEY-----\n<60 chars>\n-----END PUBLIC KEY-----\n`).

### 2.1 Rotation and revocation statements

Portable JSON objects, verifiable offline. The digest is
`sha256(canonical(statement without its signature field))`, signed as in §4.

```json
{"fsp":"0.1","type":"key-rotation","old_agent_id":"fsp:…","old_public_key":"…",
 "new_agent_id":"fsp:…","new_public_key":"…","ts":1763290000456,
 "sigs":{"old":"<b64>","new":"<b64>"}}

{"fsp":"0.1","type":"key-revocation","agent_id":"fsp:…","public_key":"…",
 "reason":"key compromised","ts":1763290000789,"sig":"<b64>"}
```

* A rotation MUST be signed by both keys: the old one authorizes, the new one
  proves possession (nobody can rotate an ID onto a key they do not hold).
* A revocation is signed by the revoked key itself. Org-level revocation by an
  endorsing key is **(planned)** with the control plane.
* An agent sends `identity.rotate` / `identity.revoke` `{statement}` over its own
  session; the hub only accepts statements about the sending agent, answers
  `identity.ack {status: "rotated" | "revoked", agent_id}`, persists the
  statement, and from then on refuses registration of that ID with `FSP-1105`.
* Peers that allow-listed the old ID in `accepts.agents` must update it;
  automatic propagation of rotations to peers is **(planned)**.

## 3. Agent card

Sent at registration, returned by discovery. Schema: `schemas/agent-card.json`.

| Field | Meaning |
|---|---|
| `agent_id` | Self-certifying ID (§2). |
| `name` | Human label, `[a-z0-9._-]{1,64}`. Not unique, not trusted. |
| `org` | Owner organization, `[a-z0-9._-]{1,64}`. Default `local`. |
| `public_key` | PEM (§2). |
| `capabilities` | List of `{name, description, risk, input_schema?}`. `risk` is `R0`…`R5` (InterMesh scale). |
| `visibility` | `private` (never listed), `org` (listed to same org, default), `public`. |
| `accepts` | `{orgs: [...], agents: [...]}` — who may send tasks. Default: the agent's own org only. |
| `runtime` | `{language, version, sdk, adapters: [...]}` — informational. |
| `enc_key` | X25519 public key (b64, 32 bytes) for end-to-end payload encryption (§4.1). |
| `card_sig` | Agent signature over the canonical card without `card_sig` (scheme of §4). **Required**: hubs refuse unsigned cards, SDKs ignore cards that do not verify. It binds `enc_key`, capabilities and accepts to the key-derived ID, so a hub cannot alter a card it relays. |

## 4. Envelope

Every frame, in both directions, is an envelope. Schema: `schemas/envelope.json`.

```json
{
  "fsp": "0.1",
  "id": "<uuid v4>",
  "type": "task.request",
  "from": "fsp:…",
  "to": "fsp:…",
  "ts": 1763290000000,
  "corr": "<id of the envelope this answers, optional>",
  "body": { },
  "sig": { "alg": "Ed25519", "kid": "<kid>", "value": "<b64>" }
}
```

Signature: `digest = hex(sha256(canonical(envelope without "sig")))`, then
`sig.value = b64(Ed25519.sign(ascii(digest)))`. This is the exact scheme of
InterMesh Action Evidence v0.1, so one verifier covers both.

Receivers MUST reject an envelope whose signature does not verify, whose
`from` does not equal the agent ID derived from the signing key, or whose
`ts` is more than 120 s away from the receiver's clock. Receivers SHOULD
drop duplicate `id`s seen in the last 10 minutes.

### 4.1 End-to-end payload encryption

The `input` of `task.request`, the `output` of `task.result` and the `data` of
`message` may be replaced by `sealed`, readable only by the recipient:

```
x25519_private = HKDF-SHA256(ikm = Ed25519 seed, salt = none, info = "fsp-0.1 x25519", 32)
shared         = X25519(ephemeral_private, recipient.enc_key)
key            = HKDF-SHA256(shared, salt = epk || recipient.enc_key, info = "fsp-0.1 payload", 32)
sealed         = {"alg": "X25519-HKDF-SHA256-A256GCM", "epk": b64, "nonce": b64(12 bytes),
                  "ct": b64(AES-256-GCM(key, nonce, canonical(data), aad) || tag)}
aad            = canonical({"type", "from", "to", "ref"})   ref = task_id, or "message:<topic>"
```

* Senders encrypt when the recipient's card verifies and carries `enc_key`
  (SDK mode `auto`, the default). In mode `required` an agent refuses to send or
  accept plaintext (`FSP-1203`). A sealed request is answered with a sealed result.
* The AAD binds a ciphertext to its envelope type, both agents and the task:
  it cannot be replayed into another task or redirected.
* Evidence hashes the **plaintext** input/output (§8), so whoever legitimately
  holds the data can check it against the evidence.
* Hubs still see metadata: who talks to whom, when, which capability, sizes.

## 5. Session

1. Agent opens the WebSocket. Hub sends `challenge` (signed by the hub):
   `{nonce, hub_id, hub_public_key, fsp_versions: ["0.1"]}`.
2. Agent sends `register`: `{nonce, card}`. The hub checks the signature
   with `card.public_key`, that `from == card.agent_id == derive(public_key)`
   and that the nonce is the one it issued (single use).
3. Hub answers `welcome` `{agent_id, hub_id, session}` or `error` and closes.

Version negotiation: the agent picks the highest version it supports from
`fsp_versions`; 0.1 is the only version today.

### 5.1 Federation

Hubs link to each other over the same WebSocket transport. The dialing hub
answers the challenge with `peer.hello {nonce, hub: {hub_id, public_key}}`; each
side MUST have the other's hub ID on an explicit allow-list (the dialer checks the
challenge signer, the listener checks the hello signer). All hub-to-hub frames are
signed by the hub key.

| Type | Body |
|---|---|
| `peer.sync` | `{agents: [card…], revocations: [statement…]}`, sent in batches of 20 after linking |
| `peer.update` | `{added: [card…], removed: [agent_id…]}` |
| `peer.revoked` | `{statement}` — verified, stored, then re-gossiped to every other peer |
| `peer.relay` | `{envelope, sender: card}` — an agent envelope for an agent on the peer hub |
| `peer.status` | `{ref, status}` — delivery outcome, turned into `routed` for the sender |

* Only `public` cards are shared, and only one hop: a hub does not re-share
  cards it learned from a peer. A non-public requester can still receive the
  `task.result` of a task it sent (reply route, bounded).
* The receiving hub re-verifies the sender card, the envelope signature, the
  revocation list, visibility and `accepts` before delivering.
* A revocation learned from a peer disconnects any local session using that key.

## 6. Message types

| Type | Direction | Body |
|---|---|---|
| `challenge` | hub → agent | §5 |
| `register` | agent → hub | `{nonce, card}` |
| `welcome` | hub → agent | `{agent_id, hub_id, session}` |
| `discover` | agent → hub | `{capability?, org?}` |
| `discover.result` | hub → agent | `{agents: [card…]}` (filtered by visibility) |
| `deliver` | hub → agent | `{envelope, sender: card}` — the original signed envelope, untouched |
| `routed` | hub → agent | `{ref, status: "delivered" \| "offline" \| "denied"}` |
| `message` | agent → agent | `{topic, data \| sealed}` — fire-and-forget |
| `task.request` | agent → agent | `{task_id, capability, input \| sealed, deadline_ms, trace?}` |
| `task.result` | agent → agent | `{task_id, status, output? \| sealed?, error?, evidence_hash?}` |
| `task.cancel` | agent → agent | `{task_id}` |
| `identity.rotate` | agent → hub | `{statement}` (§2.1) |
| `identity.revoke` | agent → hub | `{statement}` (§2.1) |
| `identity.ack` | hub → agent | `{status, agent_id}` |
| `error` | any | `{code, message, ref?}` |

Agent-to-agent envelopes travel through the hub inside `deliver`. The
receiver verifies the inner envelope against `sender.public_key` **and**
checks `derive(sender.public_key) == envelope.from`, so a hub cannot forge a
task on behalf of an agent.

## 7. Task lifecycle

```
requested ──► rejected        (unknown capability, sender not accepted, policy block)
    │
    ├──────► pending_approval ──► approval_rejected
    │                 │
    ▼                 ▼
 running ─────► completed | failed | timeout | cancelled
```

`task.result.status` is one of `completed`, `failed`, `rejected`,
`approval_rejected`, `timeout`, `cancelled`.

* **Idempotency**: a receiver that sees a `task_id` it already answered
  returns the stored result without executing again. Requesters retry with
  the same `task_id`.
* **Deadline**: `deadline_ms` is relative. The receiver aborts the handler
  when it expires and answers `timeout`.
* **Delegation boundary**: an agent can only be asked for capabilities it
  declared. The receiver re-checks `accepts` itself; the hub check is a
  convenience, not the security boundary.
* **Human approval**: capabilities at or above the agent's approval
  threshold (default `R4`) call the agent's approval handler; with no
  handler the task is `approval_rejected` (default deny).

**Tracing.** `trace` is an optional W3C Trace Context carrier
(`{"traceparent": "00-…"}`, at most 4 string entries, 512 characters). It is
inside the signed body, so it cannot be altered in transit. Receivers ignore
an invalid carrier. Spans are named `franscor.delegate` (client) and
`franscor.task` (server) and carry only metadata.

## 8. Evidence

For every task decision (completed, failed, rejected, approval outcome) the
**receiving** agent writes an InterMesh Action Evidence v0.1 record
(`specs/action-evidence-v0.md` in the repository), chained with `prev_hash`
and signed with the agent key:

* `action` = `{method: "TASK", target: "fsp://<capability>", type: "fsp.task", payload_hash: sha256(canonical(input))}`
* `authorization.policy` = `"franscor-agent"`, `rule` = the deciding rule
* `execution` = `{status, task_id, requester, response_hash?}` with
  `status` ∈ `executed`, `blocked`, `failed`, `approval_rejected`.

The task input and output are **never** stored, only their hashes. The
existing `intermesh verify` tool verifies FRANSCOR evidence unchanged.

## 9. Error codes

| Code | Meaning |
|---|---|
| `FSP-1000` | malformed frame |
| `FSP-1001` | unsupported version |
| `FSP-1002` | frame too large |
| `FSP-1100` | bad signature |
| `FSP-1101` | agent ID does not match key |
| `FSP-1102` | stale or future timestamp |
| `FSP-1103` | bad or reused nonce |
| `FSP-1104` | not registered |
| `FSP-1105` | key revoked or rotated |
| `FSP-1200` | unknown recipient / offline |
| `FSP-1201` | denied by visibility or accept policy |
| `FSP-1202` | unknown capability |
| `FSP-1203` | encryption required but missing (plaintext refused, or no verified recipient key) |
| `FSP-1300` | rate limited |
| `FSP-1400` | handler failed |
| `FSP-1401` | timeout |
| `FSP-1402` | approval rejected |

## 10. Security defaults

* Hub binds to `127.0.0.1` unless an address is passed explicitly.
* Visibility defaults to `org`; accepts default to the agent's own org.
* Rate limit per session (default 50 frames/s, burst 100).
* No payload content in logs or evidence; only hashes.
* Plain `ws://` is only acceptable on loopback. Remote hubs MUST use `wss://`
  (enforced by the SDK unless `allow_insecure=True`).
