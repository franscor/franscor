# FSP 0.2 — trust documents (changes from 0.1)

Status: **draft**, implemented by `franscor` 0.2 (Python and TypeScript). FSP 0.2 is
additive: envelopes keep `"fsp": "0.1"`, every 0.1 agent keeps working, and the new
documents carry `"fsp": "0.2"`. Design rationale: `docs/RFC-002-PASSPORT-PERMIT-BLACKBOX.md`.

| Part | Status |
|---|---|
| §1 Passports and passport CRLs | implemented |
| §2 Permits | implemented |
| §3 Black box (hub audit, Merkle checkpoints) | implemented |

## 1. Passports

### 1.1 Document

A passport is a hub's signed statement about an agent. Schema: `schemas/passport.json`.

```json
{
  "fsp": "0.2", "type": "passport", "passport_id": "pp_<32 hex>",
  "hub_id": "fsp:…", "hub_public_key": "<PEM>",
  "agent_id": "fsp:…", "org": "acme", "agent_public_key": "<PEM>",
  "capabilities": ["math.add", "text.upper"],
  "issued_at": 1763290000000, "expires_at": 1763293600000,
  "sig": "<b64>"
}
```

`sig = b64(Ed25519_hub(ascii(hex(sha256(canonical(passport without "sig"))))))` — the
signature scheme of FSP 0.1 §4. `capabilities` is sorted and de-duplicated.

### 1.2 Verification (offline)

A verifier holding the issuing hub's public key MUST reject (code in brackets):

1. a document that is not a 0.2 passport, has a missing or mistyped field, or an
   invalid `passport_id` (`FSP-1106`);
2. `hub_id ≠ derive(hub_public_key)` or `agent_id ≠ derive(agent_public_key)` (`FSP-1106`);
3. an issuer that is not a trusted hub — keys are compared by derived ID, not by PEM
   text (`FSP-1106`);
4. a signature that does not verify (`FSP-1106`);
5. when checking a sender: `agent_id ≠ envelope.from` (`FSP-1106`);
6. `issued_at` more than 120 s in the future (`FSP-1106`), `expires_at ≤ now` (`FSP-1107`);
7. a passport the issuer's CRL revokes (`FSP-1108`).

Without trusted hub keys, a verifier can only check integrity; tools MUST say so.

### 1.3 Revocation list

Each hub maintains one signed CRL. Schema: `schemas/passport-crl.json`.

```json
{"fsp": "0.2", "type": "passport-crl", "hub_id": "fsp:…", "serial": 2, "issued_at": 1763290200000,
 "revoked": [{"passport_id": "pp_…", "agent_id": "fsp:…", "revoked_at": 1763290100000,
              "reason": "key compromised", "ban": true}],
 "sig": "<b64>"}
```

* `serial` increases with every change; a verifier keeps the highest serial it has
  verified per hub and ignores older ones.
* An entry revokes its `passport_id`. With `ban: true` it also revokes every passport of
  that `agent_id` issued at or before `revoked_at`, and the hub MUST NOT issue a new
  passport to that agent (registration is refused with `FSP-1108`). `ban: false` revokes
  one passport only, for example after a capability change.
* Entries are sorted by `(revoked_at, passport_id)`.

### 1.4 Issuance and distribution

| Frame | Direction | Body |
|---|---|---|
| `welcome` | hub → agent | 0.1 fields + `passport`, `issuers`, `crls` |
| `passport.trust` | hub → agent | `{issuers: {hub_id: PEM}, crls: [crl…]}` — sent whenever issuers or CRLs change |
| `passport.renew` | agent → hub | `{}` |
| `passport.issued` | hub → agent | `{passport}` (`null` if the agent is banned) |
| `peer.crl` | hub ↔ hub | `{crl}` — sent on linking and on every change |

* The hub issues a passport at registration (default lifetime 24 h). SDKs renew it when
  less than 10 % of its lifetime (at least 5 s) remains.
* `issuers` = the agent's own hub plus the hubs it is currently federated with. An agent
  learns them over its authenticated hub session (pin the hub with `FRANSCOR_HUB_KID`).
* A peer's CRL is accepted only if signed by that peer's hub key; hubs forward verified
  peer CRLs to their agents.

### 1.5 Use in delegation

* `task.request` gains an optional `passport` field (inside the signed body).
* Receiver modes: `verify` (default: check a passport when present — backward
  compatible), `require` (refuse a task without a valid passport, `FSP-1106`), `off`.
* With a valid passport, the receiver's policy uses the **hub-attested** `org` instead of
  the self-declared one in the agent card.
* Evidence records gain `execution.passport_id`.

### 1.6 Tools

`franscor passport issue | show | verify | revoke` (Python, with hub keys);
`franscor passport show | verify` (Node.js). `franscor hub --crl FILE` loads, watches and
writes the CRL: a revocation written by `passport revoke` reaches a running hub within a
second, then every connected agent and every peer hub.

### 1.7 New error codes

| Code | Meaning |
|---|---|
| `FSP-1106` | passport invalid, untrusted, foreign or missing (in `require` mode) |
| `FSP-1107` | passport expired |
| `FSP-1108` | passport revoked, or agent banned by the hub |

## 2. Permits

### 2.1 Document

A permit is signed by the **receiving** hub of a federation link (the hub that will route
the request to its own agent) for one agent of a partner hub, bound to that agent's
passport. Schema: `schemas/permit.json`.

```json
{
  "fsp": "0.2", "type": "permit", "permit_id": "pm_<32 hex>",
  "hub_id": "fsp:…", "hub_public_key": "<PEM>",
  "peer_hub_id": "fsp:…", "agent_id": "fsp:…", "passport_id": "pp_…", "org": "globex",
  "capabilities": ["invoice.total", "fx.*"], "scopes": ["invoices:read"],
  "messages": false, "rate_per_min": 60, "max_depth": 1,
  "issued_at": 1763290000500, "expires_at": 1763291800500,
  "sig": "<b64>"
}
```

* Signature scheme of FSP 0.1 §4, as for passports. `capabilities` and `scopes` are sorted
  and de-duplicated; an entry is an exact name, `*`, or a family `prefix.*`
  (`fx.*` covers `fx.rate`, not `fxrate`).
* `peer_hub_id`, `agent_id`, `passport_id` and `org` are copied from the verified passport.
* `expires_at` = min(`issued_at` + rule TTL, passport `expires_at`): a permit never
  outlives its passport. A renewed passport gets a new permit.

### 2.2 Verification

A verifier MUST reject (code in brackets):

1. a document that is not a 0.2 permit, has a missing or mistyped field, an invalid
   `permit_id`, lists longer than 256 or negative limits (`FSP-1109`);
2. `hub_id ≠ derive(hub_public_key)`, an issuer that is not trusted (keys compared by
   derived ID), or a signature that does not verify (`FSP-1109`);
3. `agent_id ≠ envelope.from`, or a permit whose `passport_id` / `peer_hub_id` differ from
   the requester's verified passport (`FSP-1109`);
4. `issued_at` more than 120 s in the future (`FSP-1109`), `expires_at ≤ now` (`FSP-1110`);
5. a revoked `permit_id` (`FSP-1111`);
6. an action outside the permit (`FSP-1112`): a capability not covered; any requested
   scope not covered; a delegation depth above `max_depth`; a message when
   `messages` is false; more than `rate_per_min` requests per minute (hub only).

An agent trusts permits from **its own hub only**.

### 2.3 Peering file and enforcement

The peering file is the receiving hub's contract with each partner hub. Schema:
`schemas/peering.json`.

```json
{"fsp": "0.2", "type": "peering",
 "peers": [{"hub_id": "fsp:…", "name": "globex",
            "rules": [{"orgs": ["globex"], "agents": ["*"], "capabilities": ["invoice.total"],
                       "scopes": ["invoices:read"], "messages": false,
                       "rate_per_min": 60, "max_depth": 1, "ttl": "1h"}]}],
 "revoked": [{"permit_id": "pm_…", "agent_id": "fsp:…", "peer_hub_id": "fsp:…",
              "revoked_at": 1763290100000, "reason": "contract ended"}]}
```

* **With a peering file**, every `task.request` and `message` relayed by a peer hub is
  default-deny. The receiving hub, before routing:
  1. requires a passport in the request body, issued by the relaying peer hub, verified
     with that hub's key and its CRL (`FSP-1106` to `FSP-1108`);
  2. finds the first rule of that peer whose `orgs` match the attested org and whose
     `agents` match the agent ID; none → refused (`FSP-1112`);
  3. issues the permit (cached per passport) and applies §2.2 with the request's
     `capability`, `scopes` and `depth`, plus the rate limit;
  4. on success, adds `permit` to the `deliver` frame. Any refusal is answered `denied`.
* `task.result` and `task.cancel` frames for tasks the local agents requested are not
  subject to permits.
* **Without a peering file**, FSP 0.1 federation rules apply unchanged; hubs SHOULD warn.
* The file is watched. Editing it drops the cached permits, so changed rules apply to the
  next request. A revocation entry blocks its `permit_id` and, when it names an agent,
  every new permit for that agent from that peer until the entry is removed.
  `franscor permit revoke pm_…` may write the ID alone; the hub completes `agent_id` and
  `peer_hub_id` from its records.

### 2.4 Request terms

`task.request` gains two optional fields inside the signed body:

| Field | Meaning |
|---|---|
| `scopes` | data scopes the task needs (list of strings, ≤ 256) |
| `depth` | delegation depth: 0 (absent) for a task started by a user or program; an SDK serving a task at depth *d* sends *d* + 1 for any delegation made by its handler |

`message` bodies carry the sender's `passport` too, so a partner hub can admit them.

### 2.5 Receiver modes

`permit="verify"` (default): check a permit when the hub attached one; `require`: also
refuse a task from an agent whose passport was not issued by the agent's own hub when no
permit is attached (rule `permit-required`, `FSP-1109`); `off`: ignore permits. With a
valid permit, evidence records gain `execution.permit_id`.

### 2.6 Tools and error codes

`franscor hub --peering FILE`; `franscor permit show | verify | revoke` (Python),
`franscor permit show | verify` (Node.js).

| Code | Meaning |
|---|---|
| `FSP-1109` | permit invalid, untrusted, foreign, bound to another passport, or missing (`require`) |
| `FSP-1110` | permit expired |
| `FSP-1111` | permit revoked |
| `FSP-1112` | action outside the permit (capability, scope, depth, message, rate), or no rule

## 3. Black box

### 3.1 Entries

A hub with a black box appends one entry per routing decision on an agent-to-agent frame
(`task.request`, `task.result`, `task.cancel`, `message`). Schema: `schemas/audit-entry.json`.

```json
{"fsp": "0.2", "type": "audit-entry", "index": 41, "ts": 1763290001000,
 "route": "inbound", "frame": "task.request", "envelope_id": "…",
 "from": "fsp:…", "to": "fsp:…", "peer_hub_id": "fsp:…",
 "passport_id": "pp_…", "permit_id": "pm_…",
 "payload_hash": "<sha256 hex of canonical(envelope body)>",
 "decision": "blocked", "code": "FSP-1112"}
```

| `route` | Recorded by |
|---|---|
| `local` | the hub of both agents, or a hub that cannot route the frame at all |
| `outbound` | the sender's hub, when a peer hub answered (`peer.status`) or the relay failed |
| `inbound` | the receiving hub, for a frame relayed by a peer |

| `decision` | Meaning | Sender is told |
|---|---|---|
| `allowed` | delivered | `delivered` |
| `blocked` | refused (policy, permit, passport, revoked key) | `denied` |
| `masked` | refused, the target exists but may not be seen by the sender | `offline` |
| `unreachable` | no such agent, or the link or delivery failed | `offline` |

* Entries carry metadata only. `payload_hash` hashes the body as routed — the ciphertext
  when end-to-end encryption is on — so a party holding the plaintext can prove it was the
  payload, and the hub learns nothing.
* `passport_id` is the one presented in the body; it is verified by the hub only on
  inbound frames under a peering file (§2.3).
* An entry is stored and hashed as its exact canonical JSON text (FSP 0.1 §3). Field
  `index` is its position; leaves are `SHA-256(0x00 || utf8(text))`.

### 3.2 Tree and checkpoints

Entries are the leaves of an RFC 6962 / RFC 9162 §2.1 Merkle tree (node =
`SHA-256(0x01 || left || right)`, empty tree = `SHA-256("")`). The hub signs checkpoints
(schema `schemas/audit-checkpoint.json`):

```json
{"fsp": "0.2", "type": "audit-checkpoint", "hub_id": "fsp:…", "hub_public_key": "<PEM>",
 "tree_size": 42, "root": "<hex>", "ts": 1763290003000, "sig": "<b64>"}
```

Signature scheme of FSP 0.1 §4. A hub MUST NOT start when its stored entries do not
reproduce the root of its last stored checkpoint.

### 3.3 Witnessing

| Frame | Direction | Body |
|---|---|---|
| `peer.witnessed` | witness → hub, on linking | `{tree_size}`: the size of the hub's tree it last cosigned (0 if none) |
| `peer.checkpoint` | hub → witness | `{checkpoint, from_size, proof}`: RFC 9162 consistency proof from `from_size` |
| `peer.cosign` | witness → hub | `{cosignature}` |

The witness verifies the checkpoint signature with the peer's hub key, then the
consistency proof from the checkpoint it last witnessed. On success it stores the new
checkpoint and returns a cosignature (schema `schemas/audit-cosignature.json`):

```json
{"fsp": "0.2", "type": "audit-cosignature", "witness_id": "fsp:…", "witness_public_key": "<PEM>",
 "hub_id": "fsp:…", "tree_size": 42, "root": "<hex>", "checkpoint_ts": 1763290003000,
 "ts": 1763290003500, "sig": "<b64>"}
```

On failure it MUST keep both signed checkpoints and the proof as an `audit-conflict` record
and alert its operator; a proof from another size than the one it witnessed is not a
conflict, and the witness re-sends `peer.witnessed`. The first checkpoint of a hub is
accepted as is (trust on first use). Hubs without a black box ignore these frames.

### 3.4 Export and third-party verification

An export bundle (schema `schemas/audit-bundle.json`) holds the latest checkpoint, its
cosignatures, entries `[start, end)` as leaf texts, inclusion proofs when the export is
partial, and optionally a consistency proof from an earlier tree size. A verifier:

1. verifies the checkpoint signature against the hub key it obtained independently;
2. for a full export, recomputes the root from every leaf; for a partial one, checks each
   entry's inclusion proof;
3. checks every leaf is canonical JSON of an `audit-entry` with the right `index`;
4. verifies cosignatures against the witness keys it trusts;
5. with an earlier checkpoint, checks the consistency proof: the old tree is a prefix.

### 3.5 Tools

`franscor hub --audit DIR [--checkpoint-interval 60s]`; `franscor audit show | export |
verify` (Python, `export` needs no private key); `franscor audit show | verify` (Node.js).
