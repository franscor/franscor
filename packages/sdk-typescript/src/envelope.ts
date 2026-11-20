/** FSP envelopes — same signature scheme as the Python SDK and InterMesh evidence. */
import { randomUUID } from 'node:crypto';
import { CanonicalError, canonicalHash } from './canonical.js';
import { Codes, FSPError } from './errors.js';
import { AGENT_ID_RE, agentIdFromPem, kidFromPem, verifyDigest, type Identity } from './identity.js';

export const FSP_VERSION = '0.1';
export const MAX_SKEW_MS = 120_000;

export type FrameType =
  | 'challenge' | 'register' | 'welcome' | 'discover' | 'discover.result' | 'deliver'
  | 'routed' | 'message' | 'task.request' | 'task.result' | 'task.cancel' | 'error'
  | 'identity.rotate' | 'identity.revoke' | 'identity.ack'
  | 'passport.trust' | 'passport.renew' | 'passport.issued';

const TYPES = new Set<string>([
  'challenge', 'register', 'welcome', 'discover', 'discover.result', 'deliver',
  'routed', 'message', 'task.request', 'task.result', 'task.cancel', 'error',
  'identity.rotate', 'identity.revoke', 'identity.ack',
  'passport.trust', 'passport.renew', 'passport.issued',
]);

export interface Envelope<B = Record<string, unknown>> {
  fsp: '0.1';
  id: string;
  type: FrameType;
  from: string;
  to?: string;
  ts: number;
  corr?: string;
  body: B;
  sig: { alg: 'Ed25519'; kid: string; value: string };
}

export function digest(env: Record<string, unknown>): string {
  const { sig: _sig, ...rest } = env;
  return canonicalHash(rest);
}

export function seal<B extends Record<string, unknown>>(
  identity: Identity,
  type: FrameType,
  body: B,
  opts: { to?: string; corr?: string; ts?: number; id?: string } = {},
): Envelope<B> {
  const env: Record<string, unknown> = {
    fsp: FSP_VERSION,
    id: opts.id ?? randomUUID(),
    type,
    from: identity.agentId,
    ts: opts.ts ?? Date.now(),
    body,
  };
  if (opts.to) env.to = opts.to;
  if (opts.corr) env.corr = opts.corr;
  env.sig = { alg: 'Ed25519', kid: identity.kid, value: identity.signDigest(digest(env)) };
  return env as unknown as Envelope<B>;
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

export function checkShape(env: unknown): asserts env is Envelope {
  if (!isObj(env)) throw new FSPError(Codes.MALFORMED, 'frame is not a JSON object');
  if (env.fsp !== FSP_VERSION) throw new FSPError(Codes.UNSUPPORTED_VERSION, `unsupported FSP version ${String(env.fsp)}`);
  for (const [field, kind] of [['id', 'string'], ['type', 'string'], ['from', 'string'], ['ts', 'number'], ['body', 'object'], ['sig', 'object']] as const) {
    const v = env[field];
    if (typeof v !== kind || v === null || (kind === 'object' && Array.isArray(v))) {
      throw new FSPError(Codes.MALFORMED, `field '${field}' missing or not ${kind}`);
    }
  }
  if (!Number.isSafeInteger(env.ts)) throw new FSPError(Codes.MALFORMED, "'ts' must be an integer");
  if (!TYPES.has(env.type as string)) throw new FSPError(Codes.MALFORMED, `unknown type ${String(env.type)}`);
  if (!AGENT_ID_RE.test(env.from as string)) throw new FSPError(Codes.MALFORMED, "invalid 'from'");
  if ('to' in env && (typeof env.to !== 'string' || !AGENT_ID_RE.test(env.to))) throw new FSPError(Codes.MALFORMED, "invalid 'to'");
  const len = (env.id as string).length;
  if (len < 8 || len > 64) throw new FSPError(Codes.MALFORMED, "invalid 'id'");
}

export function verifyEnvelope(env: unknown, publicPem: string, opts: { now?: number; checkTime?: boolean } = {}): asserts env is Envelope {
  checkShape(env);
  let fromKey: string;
  try {
    fromKey = agentIdFromPem(publicPem);
  } catch {
    throw new FSPError(Codes.BAD_SIGNATURE, 'unreadable public key');
  }
  if (fromKey !== env.from) throw new FSPError(Codes.ID_MISMATCH, "'from' does not match the signing key");
  if (env.sig.alg !== 'Ed25519' || env.sig.kid !== kidFromPem(publicPem)) throw new FSPError(Codes.BAD_SIGNATURE, 'unexpected algorithm or key id');
  let d: string;
  try {
    d = digest(env as unknown as Record<string, unknown>);
  } catch (err) {
    if (err instanceof CanonicalError) throw new FSPError(Codes.MALFORMED, err.message);
    throw err;
  }
  if (!verifyDigest(publicPem, d, String(env.sig.value ?? ''))) throw new FSPError(Codes.BAD_SIGNATURE, 'signature does not verify');
  if (opts.checkTime !== false) {
    const now = opts.now ?? Date.now();
    if (Math.abs(now - env.ts) > MAX_SKEW_MS) throw new FSPError(Codes.STALE, 'timestamp outside the accepted window');
  }
}
