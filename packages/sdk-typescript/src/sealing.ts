/**
 * End-to-end payload encryption and signed agent cards — byte-compatible with
 * the Python SDK (`franscor.sealing`). X25519 key derived from the Ed25519 seed,
 * HKDF-SHA256, AES-256-GCM, AAD = canonical({type, from, to, ref}).
 */
import { createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, type KeyObject } from 'node:crypto';
import { b64, canonicalHash, canonicalJson, unb64 } from './canonical.js';
import { Codes, FSPError } from './errors.js';
import { agentIdFromPem, verifyDigest, type Identity } from './identity.js';

export const ALG = 'X25519-HKDF-SHA256-A256GCM';
const INFO = Buffer.from('fsp-0.1 payload');
const DERIVE_INFO = Buffer.from('fsp-0.1 x25519');
const X25519_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI = Buffer.from('302a300506032b656e032100', 'hex');

export interface Sealed {
  alg: string;
  epk: string;
  nonce: string;
  ct: string;
}

const x25519Private = (raw: Uint8Array): KeyObject => createPrivateKey({ key: Buffer.concat([X25519_PKCS8, raw]), format: 'der', type: 'pkcs8' });
const x25519Public = (raw: Uint8Array): KeyObject => createPublicKey({ key: Buffer.concat([X25519_SPKI, raw]), format: 'der', type: 'spki' });
const rawPublic = (k: KeyObject): Buffer => {
  const der = createPublicKey(k).export({ format: 'der', type: 'spki' });
  return der.subarray(der.length - 32);
};

export function encPrivateKey(identity: Identity): KeyObject {
  const seed = identity.ed25519Seed();
  return x25519Private(Buffer.from(hkdfSync('sha256', seed, Buffer.alloc(0), DERIVE_INFO, 32)));
}

export const encPublicB64 = (identity: Identity): string => b64(rawPublic(encPrivateKey(identity)));

export const aad = (type: string, from: string, to: string, ref: string): Buffer =>
  Buffer.from(canonicalJson({ type, from, to, ref }), 'utf8');

/** `ephemeralSeed` and `nonce` are injectable for test vectors only. */
export function sealPayload(data: unknown, recipientEncKey: string, aadBytes: Uint8Array, opts: { ephemeralSeed?: Uint8Array; nonce?: Uint8Array } = {}): Sealed {
  const eph = opts.ephemeralSeed ? x25519Private(opts.ephemeralSeed) : generateKeyPairSync('x25519').privateKey;
  const rpk = unb64(recipientEncKey);
  const epk = rawPublic(eph);
  const shared = diffieHellman({ privateKey: eph, publicKey: x25519Public(rpk) });
  const key = Buffer.from(hkdfSync('sha256', shared, Buffer.concat([epk, rpk]), INFO, 32));
  const nonce = Buffer.from(opts.nonce ?? randomBytes(12));
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aadBytes);
  const ct = Buffer.concat([cipher.update(canonicalJson(data), 'utf8'), cipher.final(), cipher.getAuthTag()]);
  return { alg: ALG, epk: b64(epk), nonce: b64(nonce), ct: b64(ct) };
}

export function openSealed(sealed: unknown, identity: Identity, aadBytes: Uint8Array): unknown {
  try {
    const s = sealed as Sealed;
    if (!s || s.alg !== ALG) throw new Error('unknown algorithm');
    const priv = encPrivateKey(identity);
    const rpk = rawPublic(priv);
    const epk = unb64(s.epk);
    const shared = diffieHellman({ privateKey: priv, publicKey: x25519Public(epk) });
    const key = Buffer.from(hkdfSync('sha256', shared, Buffer.concat([epk, rpk]), INFO, 32));
    const raw = unb64(s.ct);
    const decipher = createDecipheriv('aes-256-gcm', key, unb64(s.nonce));
    decipher.setAAD(aadBytes);
    decipher.setAuthTag(raw.subarray(raw.length - 16));
    const plain = Buffer.concat([decipher.update(raw.subarray(0, raw.length - 16)), decipher.final()]);
    return JSON.parse(plain.toString('utf8'));
  } catch (err) {
    throw new FSPError(Codes.BAD_SIGNATURE, `cannot open sealed payload (${err instanceof Error ? err.name : 'Error'})`);
  }
}

// -- signed cards -----------------------------------------------------------------

export function signCard<T extends Record<string, unknown>>(card: T, identity: Identity): T & { card_sig: string } {
  const { card_sig: _drop, ...body } = card as Record<string, unknown>;
  return { ...(body as T), card_sig: identity.signDigest(canonicalHash(body)) };
}

export function cardVerified(card: unknown): boolean {
  try {
    const c = card as Record<string, unknown>;
    if (!c || agentIdFromPem(String(c.public_key)) !== c.agent_id) return false;
    const { card_sig: sig, ...body } = c;
    return verifyDigest(String(c.public_key), canonicalHash(body), String(sig ?? ''));
  } catch {
    return false;
  }
}

export function encKeyOf(card: unknown): string | undefined {
  const c = card as { enc_key?: unknown } | undefined;
  return cardVerified(card) && typeof c?.enc_key === 'string' ? c.enc_key : undefined;
}
