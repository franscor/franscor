/**
 * Passports (FSP 0.2 §3.2) — same format, checks and error codes as the Python
 * SDK (`franscor.passport`). Hub-signed identity documents, verifiable offline
 * with the hub's public key; revocation through the hub's signed CRL.
 */
import { randomUUID } from 'node:crypto';
import { canonicalHash } from './canonical.js';
import { Codes, FSPError } from './errors.js';
import { agentIdFromPem, verifyDigest, type Identity } from './identity.js';

export const DOC_VERSION = '0.2';
export const DEFAULT_TTL_MS = 24 * 3600 * 1000;
const MAX_SKEW_MS = 120_000;
const PASSPORT_ID_RE = /^pp_[0-9a-f]{32}$/;

export interface Passport {
  fsp: '0.2';
  type: 'passport';
  passport_id: string;
  hub_id: string;
  hub_public_key: string;
  agent_id: string;
  org: string;
  agent_public_key: string;
  capabilities: string[];
  issued_at: number;
  expires_at: number;
  sig: string;
}

export interface CrlEntry {
  passport_id: string;
  agent_id: string;
  revoked_at: number;
  reason: string;
  ban: boolean;
}

export interface PassportCrl {
  fsp: '0.2';
  type: 'passport-crl';
  hub_id: string;
  serial: number;
  issued_at: number;
  revoked: CrlEntry[];
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

/** Issuance is a hub's job (the reference hub is Python); kept here for format parity and tests. */
export function issuePassport(hub: Identity, a: { agentId: string; org: string; agentPublicKey: string; capabilities: string[]; ttlMs?: number; now?: number; passportId?: string }): Passport {
  if (idOf(a.agentPublicKey) !== a.agentId) throw new RangeError('agentId does not match agentPublicKey');
  const issued = a.now ?? Date.now();
  const doc: Record<string, unknown> = {
    fsp: DOC_VERSION, type: 'passport', passport_id: a.passportId ?? `pp_${randomUUID().replace(/-/g, '')}`,
    hub_id: hub.agentId, hub_public_key: hub.publicPem, agent_id: a.agentId, org: a.org,
    agent_public_key: a.agentPublicKey, capabilities: [...new Set(a.capabilities)].sort(),
    issued_at: issued, expires_at: issued + (a.ttlMs ?? DEFAULT_TTL_MS),
  };
  doc.sig = hub.signDigest(digestOf(doc));
  return doc as unknown as Passport;
}

export function crlRevokes(crl: PassportCrl, p: Pick<Passport, 'passport_id' | 'agent_id' | 'issued_at'>): boolean {
  return crl.revoked.some((e) => e.passport_id === p.passport_id || (e.ban && e.agent_id === p.agent_id && p.issued_at <= e.revoked_at));
}

export interface VerifyPassportOptions {
  /** hub_id -> hub public key PEM. Without it, only integrity is checked, not trust. */
  trustedHubs?: Record<string, string>;
  /** hub_id -> that hub's verified CRL. */
  crls?: Record<string, PassportCrl>;
  agentId?: string;
  now?: number;
}

/** Throws FSPError FSP-1106 (invalid), FSP-1107 (expired) or FSP-1108 (revoked). */
export function verifyPassport(passport: unknown, opts: VerifyPassportOptions = {}): Passport {
  const p = passport as Passport;
  const fail = (code: string, message: string): never => {
    throw new FSPError(code, message);
  };
  if (!p || typeof p !== 'object' || p.type !== 'passport' || p.fsp !== DOC_VERSION) fail(Codes.PASSPORT_INVALID, 'not a passport');
  for (const [k, kind] of [['passport_id', 'string'], ['hub_id', 'string'], ['hub_public_key', 'string'], ['agent_id', 'string'], ['org', 'string'],
    ['agent_public_key', 'string'], ['issued_at', 'number'], ['expires_at', 'number'], ['sig', 'string']] as const) {
    if (typeof (p as unknown as Record<string, unknown>)[k] !== kind) fail(Codes.PASSPORT_INVALID, `field '${k}' missing or not ${kind}`);
  }
  if (!Array.isArray(p.capabilities) || !Number.isSafeInteger(p.issued_at) || !Number.isSafeInteger(p.expires_at)) fail(Codes.PASSPORT_INVALID, 'malformed passport');
  if (!PASSPORT_ID_RE.test(p.passport_id)) fail(Codes.PASSPORT_INVALID, 'invalid passport_id');
  if (idOf(p.hub_public_key) !== p.hub_id) fail(Codes.PASSPORT_INVALID, 'hub_id does not match the hub key');
  if (idOf(p.agent_public_key) !== p.agent_id) fail(Codes.PASSPORT_INVALID, 'agent_id does not match the agent key');
  if (opts.trustedHubs) {
    const trusted = opts.trustedHubs[p.hub_id];
    // Compare keys, not PEM text (line endings differ between platforms).
    if (!trusted || idOf(trusted) !== p.hub_id) fail(Codes.PASSPORT_INVALID, 'passport issued by an untrusted hub');
  }
  if (!verifyDigest(p.hub_public_key, digestOf(p as unknown as Record<string, unknown>), p.sig)) fail(Codes.PASSPORT_INVALID, 'hub signature does not verify');
  if (opts.agentId !== undefined && p.agent_id !== opts.agentId) fail(Codes.PASSPORT_INVALID, 'passport belongs to another agent');
  const now = opts.now ?? Date.now();
  if (p.issued_at > now + MAX_SKEW_MS) fail(Codes.PASSPORT_INVALID, 'passport not valid yet');
  if (p.expires_at <= now) fail(Codes.PASSPORT_EXPIRED, 'passport expired');
  const crl = opts.crls?.[p.hub_id];
  if (crl && crlRevokes(crl, p)) fail(Codes.PASSPORT_REVOKED, 'passport revoked by its hub');
  return p;
}

export function makeCrl(hub: Identity, revoked: CrlEntry[], serial: number, now = Date.now()): PassportCrl {
  const doc: Record<string, unknown> = {
    fsp: DOC_VERSION, type: 'passport-crl', hub_id: hub.agentId, serial, issued_at: now,
    revoked: [...revoked].sort((x, y) => x.revoked_at - y.revoked_at || (x.passport_id < y.passport_id ? -1 : x.passport_id > y.passport_id ? 1 : 0)),
  };
  doc.sig = hub.signDigest(digestOf(doc));
  return doc as unknown as PassportCrl;
}

export function verifyCrl(crl: unknown, hubPublicKey: string): PassportCrl {
  const c = crl as PassportCrl;
  if (!c || c.type !== 'passport-crl' || c.fsp !== DOC_VERSION) throw new FSPError(Codes.PASSPORT_INVALID, 'not a passport CRL');
  if (idOf(hubPublicKey) !== c.hub_id) throw new FSPError(Codes.PASSPORT_INVALID, 'CRL from another hub');
  if (!Number.isSafeInteger(c.serial) || !Array.isArray(c.revoked)) throw new FSPError(Codes.PASSPORT_INVALID, 'malformed CRL');
  if (!verifyDigest(hubPublicKey, digestOf(c as unknown as Record<string, unknown>), String(c.sig ?? ''))) throw new FSPError(Codes.PASSPORT_INVALID, 'CRL signature does not verify');
  return c;
}
