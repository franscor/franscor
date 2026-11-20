/** Key rotation and revocation statements — same format and checks as the Python SDK. */
import { canonicalHash } from './canonical.js';
import { Codes, FSPError } from './errors.js';
import { agentIdFromPem, verifyDigest, type Identity } from './identity.js';

const MAX_REASON = 200;

export interface RotationStatement {
  fsp: '0.1';
  type: 'key-rotation';
  old_agent_id: string;
  old_public_key: string;
  new_agent_id: string;
  new_public_key: string;
  ts: number;
  sigs: { old: string; new: string };
}

export interface RevocationStatement {
  fsp: '0.1';
  type: 'key-revocation';
  agent_id: string;
  public_key: string;
  reason: string;
  ts: number;
  sig: string;
}

function digestWithout(st: Record<string, unknown>, field: string): string {
  const { [field]: _omit, ...rest } = st;
  return canonicalHash(rest);
}

export function makeRotation(oldId: Identity, newId: Identity, ts = Date.now()): RotationStatement {
  const st: Record<string, unknown> = {
    fsp: '0.1', type: 'key-rotation',
    old_agent_id: oldId.agentId, old_public_key: oldId.publicPem,
    new_agent_id: newId.agentId, new_public_key: newId.publicPem, ts,
  };
  const d = digestWithout(st, 'sigs');
  st.sigs = { old: oldId.signDigest(d), new: newId.signDigest(d) };
  return st as unknown as RotationStatement;
}

export function makeRevocation(identity: Identity, reason = 'unspecified', ts = Date.now()): RevocationStatement {
  const st: Record<string, unknown> = {
    fsp: '0.1', type: 'key-revocation', agent_id: identity.agentId, public_key: identity.publicPem,
    reason: reason.slice(0, MAX_REASON), ts,
  };
  st.sig = identity.signDigest(digestWithout(st, 'sig'));
  return st as unknown as RevocationStatement;
}

function need(cond: boolean, message: string): asserts cond {
  if (!cond) throw new FSPError(Codes.BAD_SIGNATURE, message);
}

const idOf = (pem: unknown): string | null => {
  try {
    return agentIdFromPem(String(pem));
  } catch {
    return null;
  }
};

export function verifyRotation(st: unknown): asserts st is RotationStatement {
  const s = st as RotationStatement;
  need(!!s && s.type === 'key-rotation' && s.fsp === '0.1', 'not a key-rotation statement');
  need(idOf(s.old_public_key) === s.old_agent_id, 'old id does not match old key');
  need(idOf(s.new_public_key) === s.new_agent_id, 'new id does not match new key');
  need(s.old_agent_id !== s.new_agent_id, 'rotation to the same key');
  need(Number.isSafeInteger(s.ts), 'ts must be an integer');
  const d = digestWithout(s as unknown as Record<string, unknown>, 'sigs');
  need(verifyDigest(s.old_public_key, d, String(s.sigs?.old ?? '')), 'old key signature invalid');
  need(verifyDigest(s.new_public_key, d, String(s.sigs?.new ?? '')), 'new key signature invalid');
}

export function verifyRevocation(st: unknown): asserts st is RevocationStatement {
  const s = st as RevocationStatement;
  need(!!s && s.type === 'key-revocation' && s.fsp === '0.1', 'not a key-revocation statement');
  need(idOf(s.public_key) === s.agent_id, 'id does not match key');
  need(Number.isSafeInteger(s.ts), 'ts must be an integer');
  need(typeof s.reason === 'string' && s.reason.length <= MAX_REASON, 'bad reason');
  need(verifyDigest(s.public_key, digestWithout(s as unknown as Record<string, unknown>, 'sig'), String(s.sig ?? '')), 'signature invalid');
}
