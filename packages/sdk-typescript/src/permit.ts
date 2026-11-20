/**
 * Permits (FSP 0.2 §2) — same format, checks and error codes as the Python SDK
 * (`franscor.permit`). A permit is signed by the receiving hub of a federation
 * link, bound to the requester's passport, and bounds what that agent may do:
 * capabilities, data scopes, rate, delegation depth, expiry.
 *
 * Peering files and enforcement before routing live in the hub (Python). An
 * agent checks the permit its hub attached to a delivered task.
 */
import { randomUUID } from 'node:crypto';
import { canonicalHash } from './canonical.js';
import { Codes, FSPError } from './errors.js';
import { agentIdFromPem, verifyDigest, type Identity } from './identity.js';
import { DOC_VERSION, type Passport } from './passport.js';

export const PERMIT_TTL_MS = 3600 * 1000;
const MAX_SKEW_MS = 120_000;
const MAX_LIST = 256;
const PERMIT_ID_RE = /^pm_[0-9a-f]{32}$/;

export interface Permit {
  fsp: '0.2';
  type: 'permit';
  permit_id: string;
  hub_id: string;
  hub_public_key: string;
  peer_hub_id: string;
  agent_id: string;
  passport_id: string;
  org: string;
  capabilities: string[];
  scopes: string[];
  messages: boolean;
  rate_per_min: number;
  max_depth: number;
  issued_at: number;
  expires_at: number;
  sig: string;
}

const digestOf = (doc: Record<string, unknown>): string => {
  const { sig: _sig, ...body } = doc;
  return canonicalHash(body);
};

const idOf = (pem: unknown): string | null => {
  try {
    return agentIdFromPem(String(pem));
  } catch {
    return null;
  }
};

const names = (values: Iterable<string>): string[] => [...new Set([...values].map(String))].sort();

/** Exact name, `*` for everything, or a `prefix.*` family. */
export function permitMatches(allowed: readonly string[], name: string): boolean {
  return allowed.some((p) => p === '*' || p === name || (p.endsWith('.*') && name.startsWith(p.slice(0, -1))));
}

/** Issuance is a hub's job (the reference hub is Python); kept here for format parity and tests. */
export function issuePermit(hub: Identity, passport: Pick<Passport, 'hub_id' | 'agent_id' | 'passport_id' | 'org' | 'expires_at'>, a: {
  capabilities: string[]; scopes?: string[]; messages?: boolean; ratePerMin?: number; maxDepth?: number;
  ttlMs?: number; now?: number; permitId?: string;
}): Permit {
  const issued = a.now ?? Date.now();
  const doc: Record<string, unknown> = {
    fsp: DOC_VERSION, type: 'permit', permit_id: a.permitId ?? `pm_${randomUUID().replace(/-/g, '')}`,
    hub_id: hub.agentId, hub_public_key: hub.publicPem, peer_hub_id: passport.hub_id,
    agent_id: passport.agent_id, passport_id: passport.passport_id, org: passport.org,
    capabilities: names(a.capabilities), scopes: names(a.scopes ?? []), messages: Boolean(a.messages),
    rate_per_min: a.ratePerMin ?? 60, max_depth: a.maxDepth ?? 0,
    issued_at: issued, expires_at: Math.min(issued + (a.ttlMs ?? PERMIT_TTL_MS), passport.expires_at),
  };
  doc.sig = hub.signDigest(digestOf(doc));
  return doc as unknown as Permit;
}

export interface VerifyPermitOptions {
  /** hub_id -> PEM of the hubs whose permits count (for an agent: its own hub). Without it, integrity only. */
  trustedHubs?: Record<string, string>;
  agentId?: string;
  /** The requester's (already verified) passport the permit must be bound to. */
  passport?: Pick<Passport, 'passport_id' | 'hub_id'>;
  capability?: string;
  scopes?: readonly string[];
  depth?: number;
  message?: boolean;
  revoked?: Iterable<string>;
  now?: number;
}

const FIELDS = [['permit_id', 'string'], ['hub_id', 'string'], ['hub_public_key', 'string'], ['peer_hub_id', 'string'],
  ['agent_id', 'string'], ['passport_id', 'string'], ['org', 'string'], ['messages', 'boolean'],
  ['rate_per_min', 'number'], ['max_depth', 'number'], ['issued_at', 'number'], ['expires_at', 'number'], ['sig', 'string']] as const;

/**
 * Throws FSPError FSP-1109 (invalid / untrusted / foreign), FSP-1110 (expired),
 * FSP-1111 (revoked) or FSP-1112 (action outside the permit).
 */
export function verifyPermit(permit: unknown, opts: VerifyPermitOptions = {}): Permit {
  const p = permit as Permit;
  const fail = (code: string, message: string): never => {
    throw new FSPError(code, message);
  };
  if (!p || typeof p !== 'object' || p.type !== 'permit' || p.fsp !== DOC_VERSION) fail(Codes.PERMIT_INVALID, 'not a permit');
  const rec = p as unknown as Record<string, unknown>;
  for (const [k, kind] of FIELDS) {
    if (typeof rec[k] !== kind) fail(Codes.PERMIT_INVALID, `field '${k}' missing or not ${kind}`);
  }
  for (const k of ['rate_per_min', 'max_depth', 'issued_at', 'expires_at'] as const) {
    if (!Number.isSafeInteger(p[k])) fail(Codes.PERMIT_INVALID, `field '${k}' missing or not int`);
  }
  if (!Array.isArray(p.capabilities) || !Array.isArray(p.scopes)) fail(Codes.PERMIT_INVALID, 'malformed capability or scope list');
  if (p.capabilities.length > MAX_LIST || p.scopes.length > MAX_LIST || ![...p.capabilities, ...p.scopes].every((x) => typeof x === 'string')) {
    fail(Codes.PERMIT_INVALID, 'malformed capability or scope list');
  }
  if (!PERMIT_ID_RE.test(p.permit_id)) fail(Codes.PERMIT_INVALID, 'invalid permit_id');
  if (p.rate_per_min < 0 || p.max_depth < 0) fail(Codes.PERMIT_INVALID, 'negative limit');
  if (idOf(p.hub_public_key) !== p.hub_id) fail(Codes.PERMIT_INVALID, 'hub_id does not match the hub key');
  if (opts.trustedHubs) {
    const trusted = opts.trustedHubs[p.hub_id];
    if (!trusted || idOf(trusted) !== p.hub_id) fail(Codes.PERMIT_INVALID, 'permit issued by an untrusted hub');
  }
  if (!verifyDigest(p.hub_public_key, digestOf(rec), p.sig)) fail(Codes.PERMIT_INVALID, 'hub signature does not verify');
  if (opts.agentId !== undefined && p.agent_id !== opts.agentId) fail(Codes.PERMIT_INVALID, 'permit belongs to another agent');
  if (opts.passport && (opts.passport.passport_id !== p.passport_id || opts.passport.hub_id !== p.peer_hub_id)) {
    fail(Codes.PERMIT_INVALID, 'permit is bound to another passport');
  }
  const now = opts.now ?? Date.now();
  if (p.issued_at > now + MAX_SKEW_MS) fail(Codes.PERMIT_INVALID, 'permit not valid yet');
  if (p.expires_at <= now) fail(Codes.PERMIT_EXPIRED, 'permit expired');
  if (new Set(opts.revoked ?? []).has(p.permit_id)) fail(Codes.PERMIT_REVOKED, 'permit revoked');
  if (opts.message) {
    if (!p.messages) fail(Codes.PERMIT_DENIED, 'the permit does not allow messages');
  } else if (opts.capability !== undefined && !permitMatches(p.capabilities, opts.capability)) {
    fail(Codes.PERMIT_DENIED, `capability '${opts.capability}' is not in the permit`);
  }
  const outside = (opts.scopes ?? []).find((s) => !permitMatches(p.scopes, s));
  if (outside !== undefined) fail(Codes.PERMIT_DENIED, `scope '${outside}' is not in the permit`);
  if ((opts.depth ?? 0) > p.max_depth) fail(Codes.PERMIT_DENIED, `delegation depth ${opts.depth} exceeds ${p.max_depth}`);
  return p;
}

/** Scopes and depth declared in a task.request body (validated). */
export function requestTerms(body: Record<string, unknown>): { scopes: string[]; depth: number } {
  const scopes = body.scopes ?? [];
  const depth = body.depth ?? 0;
  if (!Array.isArray(scopes) || scopes.length > MAX_LIST || !scopes.every((s) => typeof s === 'string')) {
    throw new FSPError(Codes.MALFORMED, 'scopes must be a list of strings');
  }
  if (typeof depth !== 'number' || !Number.isSafeInteger(depth) || depth < 0 || depth > 64) {
    throw new FSPError(Codes.MALFORMED, 'depth must be an integer between 0 and 64');
  }
  return { scopes: scopes as string[], depth };
}
