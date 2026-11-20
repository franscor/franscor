/**
 * Black box (FSP 0.2 §3), verifier side — same formats and checks as the Python
 * SDK (`franscor.merkle`, `franscor.blackbox`). Hubs keep the log (Python);
 * anyone can verify a signed checkpoint, its cosignatures and an export bundle
 * with the hub's public key only.
 *
 * Merkle tree of RFC 6962 / RFC 9162 §2.1: leaf = SHA-256(0x00 || bytes),
 * node = SHA-256(0x01 || left || right), empty tree = SHA-256("").
 */
import { createHash } from 'node:crypto';
import { canonicalHash, canonicalJson } from './canonical.js';
import { agentIdFromPem, verifyDigest } from './identity.js';

const sha = (...parts: Uint8Array[]): Buffer => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};
const ZERO = Uint8Array.of(0);
const ONE = Uint8Array.of(1);

export const EMPTY_ROOT = sha();
export const leafHash = (data: Uint8Array): Buffer => sha(ZERO, data);
export const nodeHash = (left: Uint8Array, right: Uint8Array): Buffer => sha(ONE, left, right);

const split = (n: number): number => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};

/** Root of a list of leaf hashes. */
export function merkleRoot(leaves: readonly Uint8Array[]): Buffer {
  const mth = (start: number, size: number): Buffer => {
    if (size === 0) return EMPTY_ROOT;
    if (size === 1) return Buffer.from(leaves[start]!);
    const k = split(size);
    return nodeHash(mth(start, k), mth(start + k, size - k));
  };
  return mth(0, leaves.length);
}

/** RFC 9162 §2.1.3.2. `leaf` is the leaf hash. */
export function verifyInclusion(leaf: Uint8Array, index: number, size: number, proof: readonly Uint8Array[], root: Uint8Array): boolean {
  if (!(Number.isSafeInteger(index) && Number.isSafeInteger(size) && index >= 0 && index < size)) return false;
  let fn = BigInt(index);
  let sn = BigInt(size - 1);
  let r = Buffer.from(leaf);
  for (const p of proof) {
    if (sn === 0n) return false;
    if (fn & 1n || fn === sn) {
      r = nodeHash(p, r);
      if (!(fn & 1n)) {
        while (!(fn & 1n) && fn !== 0n) {
          fn >>= 1n;
          sn >>= 1n;
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && r.equals(root);
}

/** RFC 9162 §2.1.4.2, plus the trivial cases (first = 0, first = second). */
export function verifyConsistency(first: number, second: number, firstRoot: Uint8Array, secondRoot: Uint8Array, proof: readonly Uint8Array[]): boolean {
  if (!(Number.isSafeInteger(first) && Number.isSafeInteger(second) && first >= 0 && first <= second)) return false;
  if (first === second) return proof.length === 0 && Buffer.from(firstRoot).equals(secondRoot);
  if (first === 0) return proof.length === 0 && Buffer.from(firstRoot).equals(EMPTY_ROOT);
  if (proof.length === 0) return false;
  const path = (first & (first - 1)) === 0 ? [firstRoot, ...proof] : [...proof];
  let fn = BigInt(first - 1);
  let sn = BigInt(second - 1);
  while (fn & 1n) {
    fn >>= 1n;
    sn >>= 1n;
  }
  let fr = Buffer.from(path[0]!);
  let sr = Buffer.from(path[0]!);
  for (const c of path.slice(1)) {
    if (sn === 0n) return false;
    if (fn & 1n || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      if (!(fn & 1n)) {
        while (!(fn & 1n) && fn !== 0n) {
          fn >>= 1n;
          sn >>= 1n;
        }
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return fr.equals(firstRoot) && sr.equals(secondRoot) && sn === 0n;
}

// -- documents ------------------------------------------------------------------------

export interface AuditCheckpoint {
  fsp: '0.2'; type: 'audit-checkpoint'; hub_id: string; hub_public_key: string;
  tree_size: number; root: string; ts: number; sig: string;
}

export interface AuditCosignature {
  fsp: '0.2'; type: 'audit-cosignature'; witness_id: string; witness_public_key: string;
  hub_id: string; tree_size: number; root: string; checkpoint_ts: number; ts: number; sig: string;
}

export interface AuditBundle {
  fsp: '0.2'; type: 'audit-bundle'; hub_id: string; hub_public_key: string;
  checkpoint: AuditCheckpoint; cosignatures: AuditCosignature[];
  entries: { index: number; leaf: string }[];
  proofs?: Record<string, string[]>;
  consistency?: { from_size: number; from_checkpoint?: AuditCheckpoint | null; proof: string[] };
}

export class AuditError extends Error {
  override name = 'AuditError';
}

const digestOf = (doc: Record<string, unknown>): string => {
  const { sig: _sig, ...body } = doc;
  return canonicalHash(body);
};

const sameKey = (pem: unknown, id: unknown): boolean => {
  try {
    return agentIdFromPem(String(pem)) === id;
  } catch {
    return false;
  }
};

const fromHex = (h: string): Buffer => {
  if (!/^[0-9a-f]{64}$/.test(h)) throw new AuditError('malformed hash');
  return Buffer.from(h, 'hex');
};

export function verifyCheckpoint(cp: unknown, hubPublicKey?: string): AuditCheckpoint {
  const c = cp as AuditCheckpoint;
  if (!c || typeof c !== 'object' || c.type !== 'audit-checkpoint' || c.fsp !== '0.2') throw new AuditError('not an audit checkpoint');
  for (const [k, kind] of [['hub_id', 'string'], ['hub_public_key', 'string'], ['tree_size', 'number'], ['root', 'string'], ['ts', 'number'], ['sig', 'string']] as const) {
    if (typeof (c as unknown as Record<string, unknown>)[k] !== kind) throw new AuditError(`checkpoint field '${k}' missing or not ${kind}`);
  }
  if (!Number.isSafeInteger(c.tree_size) || c.tree_size < 0 || !Number.isSafeInteger(c.ts) || c.root.length !== 64) throw new AuditError('malformed checkpoint');
  if (!sameKey(c.hub_public_key, c.hub_id)) throw new AuditError('checkpoint hub_id does not match its key');
  if (hubPublicKey !== undefined && !sameKey(hubPublicKey, c.hub_id)) throw new AuditError('checkpoint from another hub');
  if (!verifyDigest(c.hub_public_key, digestOf(c as unknown as Record<string, unknown>), c.sig)) throw new AuditError('checkpoint signature does not verify');
  return c;
}

export function verifyCosignature(cs: unknown, cp: AuditCheckpoint, witnessPublicKey?: string): AuditCosignature {
  const s = cs as AuditCosignature;
  if (!s || typeof s !== 'object' || s.type !== 'audit-cosignature' || s.fsp !== '0.2') throw new AuditError('not a cosignature');
  if (s.hub_id !== cp.hub_id || s.tree_size !== cp.tree_size || s.root !== cp.root || s.checkpoint_ts !== cp.ts) throw new AuditError('cosignature is for another checkpoint');
  if (!sameKey(s.witness_public_key, s.witness_id)) throw new AuditError('witness_id does not match its key');
  if (witnessPublicKey !== undefined && !sameKey(witnessPublicKey, s.witness_id)) throw new AuditError('cosignature from another witness');
  if (!verifyDigest(String(s.witness_public_key), digestOf(s as unknown as Record<string, unknown>), String(s.sig ?? ''))) throw new AuditError('cosignature does not verify');
  return s;
}

export interface BundleReport {
  valid: boolean;
  errors: string[];
  entries: number;
  witnesses: string[];
  issuer_checked: boolean;
  hub_id?: string;
  tree_size?: number;
  root?: string;
  checkpoint_ts?: number;
  extends_previous?: boolean;
}

export interface VerifyBundleOptions {
  /** The hub's public key obtained independently; otherwise integrity only. */
  hubPublicKey?: string;
  /** witness_id -> PEM of the peers whose cosignatures count. */
  witnessKeys?: Record<string, string>;
  /** An earlier checkpoint of the same hub the bundle must extend. */
  previous?: unknown;
}

/** Same report as Python's `verify_bundle`. Never throws. */
export function verifyBundle(bundle: unknown, opts: VerifyBundleOptions = {}): BundleReport {
  const report: BundleReport = { valid: false, errors: [], entries: 0, witnesses: [], issuer_checked: opts.hubPublicKey !== undefined };
  try {
    const b = bundle as AuditBundle;
    if (!b || typeof b !== 'object' || b.type !== 'audit-bundle') throw new AuditError('not an audit bundle');
    const cp = verifyCheckpoint(b.checkpoint, opts.hubPublicKey ?? String(b.hub_public_key ?? ''));
    if (cp.hub_id !== b.hub_id) throw new AuditError('bundle and checkpoint name different hubs');
    Object.assign(report, { hub_id: cp.hub_id, tree_size: cp.tree_size, root: cp.root, checkpoint_ts: cp.ts });
    const size = cp.tree_size;
    const root = fromHex(cp.root);
    const entries = Array.isArray(b.entries) ? b.entries : [];
    const idx = entries.map((e) => e?.index);
    if (idx.length && (!idx.every((i) => Number.isSafeInteger(i)) || idx.some((i, n) => i !== idx[0]! + n) || idx[0]! < 0 || idx[idx.length - 1]! >= size)) {
      throw new AuditError('entries must be consecutive indexes of the signed tree');
    }
    const proofs = b.proofs;
    if (proofs === undefined || proofs === null) {
      if (idx.length !== size || (size > 0 && idx[0] !== 0)) throw new AuditError('a bundle without proofs must hold every entry');
      if (!merkleRoot(entries.map((e) => leafHash(Buffer.from(String(e.leaf), 'utf8')))).equals(root)) throw new AuditError('entries do not produce the signed root');
    }
    for (const e of entries) {
      const leaf = String(e.leaf);
      const doc = JSON.parse(leaf) as Record<string, unknown>;
      if (canonicalJson(doc) !== leaf || doc.index !== e.index || doc.type !== 'audit-entry') throw new AuditError(`entry ${e.index} is not a canonical audit entry`);
      if (proofs) {
        const proof = (proofs[String(e.index)] ?? []).map(fromHex);
        if (!verifyInclusion(leafHash(Buffer.from(leaf, 'utf8')), e.index, size, proof, root)) throw new AuditError(`entry ${e.index} is not in the signed tree`);
      }
    }
    report.entries = entries.length;
    for (const cs of b.cosignatures ?? []) {
      const wid = String((cs as AuditCosignature | undefined)?.witness_id ?? '');
      if (opts.witnessKeys && !(wid in opts.witnessKeys)) continue;
      try {
        verifyCosignature(cs, cp, opts.witnessKeys?.[wid]);
        report.witnesses.push(wid);
      } catch (err) {
        report.errors.push(`cosignature of ${wid}: ${(err as Error).message}`);
      }
    }
    if (opts.previous !== undefined) {
      const prev = verifyCheckpoint(opts.previous, opts.hubPublicKey ?? cp.hub_public_key);
      const cons = b.consistency;
      if (!cons || prev.tree_size !== cons.from_size) throw new AuditError('the bundle has no consistency proof from the previous checkpoint');
      if (!verifyConsistency(prev.tree_size, size, fromHex(prev.root), root, (cons.proof ?? []).map(fromHex))) throw new AuditError('history was rewritten since the previous checkpoint');
      report.extends_previous = true;
    }
    report.valid = report.errors.length === 0;
  } catch (err) {
    report.errors.push((err as Error).message);
  }
  return report;
}
