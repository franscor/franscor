# RFC-002 — Passport, Permit, Black box

| | |
|---|---|
| Status | **Draft** — Passport, Permit and Black box implemented |
| Applies to | FRANSCOR / FSP 0.2 (`franscor/protocol/FSP-0.2.md`) |
| Builds on | RFC-001 (core protocol), FSP 0.1 (Ed25519 identity, signed envelopes, hub federation, evidence chain) |

## 1. Problem

FSP 0.1 proves *who sent a frame* (self-certifying Ed25519 IDs) and *what an agent
decided* (signed evidence chain). Three questions remain open once hubs of different
organizations federate:

1. **Who vouches for an agent?** An agent card is signed by the agent itself: its
   organization and capabilities are self-declared.
2. **What may a foreign agent do here?** Federation shares public agents; the receiving
   organization has no per-partner contract enforced before routing.
3. **Can a hub rewrite what it routed?** Hub logs are local; nothing stops a hub from
   editing its own history after the fact.

## 2. Passport (implemented)

A **passport** is a short-lived document in which a hub attests an agent's ID, key,
organization and capabilities, signed with the hub's Ed25519 key, verifiable offline,
revocable through a signed CRL. Normative text: FSP 0.2 §1.

Decisions and why:

* **Hub-signed, not CA-signed.** Every FSP deployment already has a hub with a key, and
  federated hubs already allow-list each other's keys. Reusing that trust graph avoids
  introducing a certificate authority.
* **Short lifetime (24 h) plus CRL.** Expiry bounds the damage of a CRL that has not
  propagated yet; the CRL handles the urgent case.
* **Ban by default on revocation.** Revoking only the passport would let the agent obtain
  a new one by reconnecting. `ban: true` closes that path; `--no-ban` exists for benign
  re-issuance.
* **Receiver enforces.** As with all FSP authorization, the agent that executes is the
  security boundary; hubs distribute trust material but are not trusted to filter.
* **Attested organization.** With a valid passport, policies use the org the hub attests,
  not the one the agent claims.
* **Backward compatible.** `verify` mode (default) accepts 0.1 agents without passports;
  `require` mode is the strict setting.

Threats addressed and tested (Python and Node.js): forged passport (unknown hub, swapped
issuer fields), tampered fields (capabilities, org, expiry), replay of another agent's
passport, expired and not-yet-valid passports, revoked passport, banned agent
reconnecting, forged or foreign CRL, revocation across federated hubs.

Residual risks: a CRL protects only once it has reached the verifier (bounded by
passport lifetime); a hub that is compromised can issue passports for agents it hosts;
agents learn trusted issuers from their own hub (pin it with `FRANSCOR_HUB_KID`).

## 3. Permit (implemented)

A **permit** is issued and signed by the *receiving* hub of a federation link, bound to a
passport: allowed capabilities, data scopes, rate limit, maximum delegation depth,
expiry. Anything not in the permit is refused **before routing**. Permits are produced
from a peering file, can be revoked immediately, and their IDs appear in evidence
records (`execution.permit_id`). Normative text: FSP 0.2 §2.

Decisions and why:

* **Issued on first use, not handed out in advance.** The receiving hub evaluates the
  peering rules against the partner agent's verified passport when its first request
  arrives, then caches the permit per passport. The partner hub never holds permits for
  the other side, so there is nothing to steal or replay there, and a rule change takes
  effect on the next request.
* **Bound to the passport, never longer-lived.** A permit names the passport it was issued
  for and expires with it at the latest; a renewed passport gets a new permit. A stolen
  permit is useless without the agent's key and passport.
* **Default-deny only with a peering file.** Without one, a hub keeps the FSP 0.1
  federation behaviour and warns at start-up: no existing deployment breaks.
* **Checked twice.** The hub refuses before routing (so a refused request never reaches
  the agent); the executing agent verifies the permit again against its own hub key
  (FSP rule: the receiver enforces). `permit="require"` lets an agent refuse partner
  agents even behind a hub without a peering file.
* **Revocation sticks.** A revoked permit blocks that agent for that partner until the
  entry is removed from the peering file; reconnecting or renewing the passport does not
  help. The file is the interface for offline revocation, as the CRL is for passports.
* **Refusals look like 0.1 refusals.** The requester sees `denied` (FSP-1201); details stay
  in the receiving hub's log. The Black box will record them.

Threats addressed and tested (Python and Node.js): forged permit (unknown hub, swapped
issuer fields), tampered fields (capabilities, scopes, depth, rate, expiry, agent),
permit of another agent or bound to another passport, expired, not-yet-valid and revoked
permits, capability / scope / depth / message outside the permit, rate limit, partner
agent without passport, partner org without a rule, revocation by API and by file on a
running hub, refusal by the executing agent in `require` mode.

Known limits, stated up front:

* delegation depth is reported by the delegating SDKs and is only reliable between honest
  ones; the permit's capability list still bounds what a dishonest agent can reach;
* scopes are declared by the requester and checked against the permit; FRANSCOR does not
  inspect payloads (they are end-to-end encrypted), so a scope bounds what a requester may
  ask for, not what the data actually contains; handlers do not see the scopes yet;
* the rate limit and revocations are enforced by the receiving hub; an agent cannot check
  either on its own;
* permits are issued per receiving hub; one hop only, as federation itself.

## 4. Black box (implemented)

Every routing decision of a hub becomes an audit entry: passport ID, permit ID, payload
hash (of the encrypted body — hubs never see plaintext), decision `allowed`, `blocked`,
`masked` (refused while answering "offline", so as not to reveal a hidden agent) or
`unreachable`. Entries form an RFC 6962 Merkle tree; the hub periodically signs a
checkpoint `{hub_id, tree_size, root, ts}` and sends it to its peers with a consistency
proof, so a single hub cannot rewrite history its peers have witnessed. An export bundle
is verifiable by a third party with `franscor audit verify` (Python or Node.js), using
public keys only. Normative text: FSP 0.2 §3.

Decisions and why:

* **RFC 6962 as is.** Certificate Transparency's tree, proofs and test vectors are well
  reviewed; our roots match its published values. Nothing new to trust.
* **A fourth decision, `unreachable`.** The draft listed three; a frame to an agent that
  does not exist (or a failed link) is neither a refusal nor a masked one, and calling it
  `blocked` would make the log lie.
* **Leaves are stored as the hashed text.** Verifiers hash bytes and never re-serialize,
  so a third-party script needs SHA-256 and Ed25519, not our canonical JSON encoder.
* **Peers as witnesses.** Federation already links hubs of different organizations with
  authenticated channels; each peer is a natural, independent witness. Witnessing is
  opt-in with the black box and invisible to hubs without one.
* **Fail closed at start, keep running on peer conflicts.** A hub whose own files do not
  match its last checkpoint refuses to start. A witness that detects a conflict keeps the
  evidence and alerts, but does not cut the link: availability is the operator's call.
* **Opt-in.** Without `--audit`, hubs keep FSP 0.1 behaviour; the log grows with traffic and
  belongs on durable storage.

Threats addressed and tested (Python and Node.js): edited, removed, reordered or
re-indexed entries; non-canonical leaves; forged or re-rooted checkpoints; checkpoint of
another hub; cosignature for another checkpoint; tampered inclusion proofs; history
rewritten and fully re-signed with the hub's own key (caught by the peer, which keeps both
signed checkpoints, across restarts); a later export that does not extend an earlier one.

Known limits:

* checkpoints prevent rewriting the past, not lying at the time of writing: a hub can
  omit a decision before it enters the log;
* entries after the last witnessed checkpoint can still be dropped; the checkpoint
  interval bounds that window;
* the first checkpoint a witness sees is trusted as is;
* a hub and all its peers colluding can rewrite history together;
* the log is single-file storage on the hub's disk (no rotation or archival yet).

## 5. Compatibility

Envelopes stay `"fsp": "0.1"`. New fields are optional, new frames are ignored by 0.1
agents, and the defaults (`passport="verify"`, `permit="verify"`, no peering file) preserve
0.1 behaviour.
