# Changelog — FRANSCOR SDK

Python package `franscor` (PyPI) and Node.js package `franscor` (npm) share one version
number. Format: [Keep a Changelog](https://keepachangelog.com/); versions follow
[Semantic Versioning](https://semver.org/) — before 1.0, a minor version may break the API.

## 0.2.0 — 2026-11-20

First public release, on PyPI (`pip install franscor`) and npm (`npm install franscor`). Alpha: not externally audited yet.

### Core (FSP 0.1)
- Self-certifying Ed25519 agent identities (`fsp:` IDs), signed envelopes, canonical JSON
  identical in Python and TypeScript (shared test vectors).
- `franscor.connect()` / `connect()`: detect, adapt, register, discover, delegate, with
  retries that never execute a task twice.
- Receiver-side, default-deny policy (organizations, agents, risk levels R0–R5, human
  approval from R4).
- Signed evidence chain for every decision, in the InterMesh Action Evidence v0.1 format.
- End-to-end encryption of task inputs, outputs and messages (X25519 + AES-256-GCM).
- Key rotation and revocation; OS keychain and encrypted key files.
- Adapters: plain functions, LangChain / LangGraph, OpenAI Agents, AutoGen; MCP and A2A
  bridges in both directions (Python), MCP tool import (TypeScript).
- OpenTelemetry traces across languages.
- Reference hub (Python): routing, discovery, rate limits, federation between hubs with
  mutual allow-lists and revocation gossip, read-only operator channel for the console.

### Trust documents (FSP 0.2, RFC-002)
- **Passports:** hub-signed identity documents, verifiable offline, with a signed
  revocation list; `passport="verify" | "require" | "off"`.
- **Permits:** with a peering file, partner agents are admitted only within a permit
  (capabilities, data scopes, rate, delegation depth, expiry), checked by the receiving
  hub before routing and again by the executing agent; `permit=...`, `scopes=[...]`.
- **Black box:** every routing decision in an RFC 6962 Merkle log, signed checkpoints
  cosigned by partner hubs, export bundles verifiable by a third party with public keys.

### Command line
- Python: `franscor hub | identity | verify | detect | bridge | revoke | passport | permit | audit`.
- Node.js: `franscor detect | identity | verify | passport | permit | audit`.

### Known limits
- No external security audit yet.
- The hub is a single process; federation is one hop.
- Delegation depth is reported by the SDKs (reliable between honest agents only).
- See `docs/RFC-002-PASSPORT-PERMIT-BLACKBOX.md` and `ARCHITECTURE.md` for the full list.

## 0.1.0 — never published

Internal milestone (FSP 0.1 core, M1–M4). Its content is part of 0.2.0.
