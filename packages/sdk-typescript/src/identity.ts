/**
 * Agent identity: Ed25519 key pair + self-certifying agent ID.
 *   agentId = "fsp:" + sha256(raw public key)[:32]
 *   kid     = sha256(public key PEM)[:16]
 * Key files are shared with the Python SDK ($FRANSCOR_HOME/identities/<name>.key).
 */
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { inspect } from 'node:util';
import { b64, unb64 } from './canonical.js';

export const NAME_RE = /^[a-z0-9._-]{1,64}$/;
export const AGENT_ID_RE = /^fsp:[0-9a-f]{32}$/;
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export function franscorHome(): string {
  return process.env.FRANSCOR_HOME || join(homedir(), '.franscor');
}

// Parsed keys and derived IDs are cached: every frame verification needs them.
const MAX_CACHE = 4096;
const keyCache = new Map<string, KeyObject>();
const idCache = new Map<string, string>();
const kidCache = new Map<string, string>();

function remember<V>(cache: Map<string, V>, k: string, make: () => V): V {
  let v = cache.get(k);
  if (v === undefined) {
    v = make();
    if (cache.size >= MAX_CACHE) cache.delete(cache.keys().next().value!);
    cache.set(k, v);
  }
  return v;
}

const publicKey = (pem: string): KeyObject => remember(keyCache, pem, () => createPublicKey(pem));

export function agentIdFromPem(pem: string): string {
  return remember(idCache, pem, () => {
    const der = publicKey(pem).export({ format: 'der', type: 'spki' });
    const raw = der.subarray(der.length - 32);
    return 'fsp:' + createHash('sha256').update(raw).digest('hex').slice(0, 32);
  });
}

export function kidFromPem(pem: string): string {
  return remember(kidCache, pem, () => createHash('sha256').update(pem, 'utf8').digest('hex').slice(0, 16));
}

export function verifyDigest(pem: string, digestHex: string, signature: string): boolean {
  try {
    const key = publicKey(pem);
    if (key.asymmetricKeyType !== 'ed25519') return false;
    return verify(null, Buffer.from(digestHex, 'ascii'), key, unb64(signature));
  } catch {
    return false;
  }
}

export class Identity {
  readonly #key: KeyObject;
  readonly publicPem: string;
  readonly agentId: string;
  readonly kid: string;

  constructor(privateKey: KeyObject) {
    if (privateKey.asymmetricKeyType !== 'ed25519') throw new TypeError('expected an Ed25519 private key');
    this.#key = privateKey;
    this.publicPem = createPublicKey(privateKey).export({ format: 'pem', type: 'spki' }).toString();
    this.agentId = agentIdFromPem(this.publicPem);
    this.kid = kidFromPem(this.publicPem);
  }

  static generate(): Identity {
    return new Identity(generateKeyPairSync('ed25519').privateKey);
  }

  /** Deterministic identity — for test vectors only. */
  static fromSeed(seed: Uint8Array): Identity {
    if (seed.length !== 32) throw new RangeError('seed must be 32 bytes');
    return new Identity(createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8' }));
  }

  /** Raw 32-byte Ed25519 seed — used only to derive the X25519 encryption key. */
  ed25519Seed(): Buffer {
    const der = this.#key.export({ format: 'der', type: 'pkcs8' });
    return der.subarray(der.length - 32);
  }

  signDigest(digestHex: string): string {
    return b64(sign(null, Buffer.from(digestHex, 'ascii'), this.#key));
  }

  /** PKCS#8 PEM, encrypted when FRANSCOR_KEY_PASSPHRASE is set. Store it, never log it. */
  privatePem(): string {
    const passphrase = process.env.FRANSCOR_KEY_PASSPHRASE || undefined;
    return this.#key.export(
      passphrase ? { format: 'pem', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase } : { format: 'pem', type: 'pkcs8' },
    ).toString();
  }

  /** Persist under `name`. With `replace`, the previous key is kept as `<name>.key.rotated-<ms>`. */
  save(name: string, opts: { home?: string; replace?: boolean } = {}): void {
    const path = Identity.pathFor(name, opts.home);
    if (existsSync(path)) {
      if (!opts.replace) throw new Error(`${path} exists`);
      renameSync(path, `${path}.rotated-${Date.now()}`);
    }
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, this.privatePem(), { mode: 0o600, flag: 'wx' });
  }

  static pathFor(name: string, home?: string): string {
    if (!NAME_RE.test(name)) throw new RangeError(`invalid identity name ${JSON.stringify(name)} (allowed: a-z 0-9 . _ -)`);
    return join(home ?? franscorHome(), 'identities', `${name}.key`);
  }

  static loadOrCreate(name: string, home?: string): Identity {
    const path = Identity.pathFor(name, home);
    const passphrase = process.env.FRANSCOR_KEY_PASSPHRASE || undefined;
    if (existsSync(path)) {
      return new Identity(createPrivateKey({ key: readFileSync(path), format: 'pem', passphrase }));
    }
    const identity = Identity.generate();
    const pem = identity.privatePem();
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    try {
      chmodSync(dirname(path), 0o700);
    } catch {
      /* best effort on platforms without POSIX modes */
    }
    writeFileSync(path, pem, { mode: 0o600, flag: 'wx' });
    return identity;
  }

  toJSON(): { agentId: string; kid: string } {
    return { agentId: this.agentId, kid: this.kid };
  }

  [inspect.custom](): string {
    return `Identity(${this.agentId}, kid=${this.kid})`;
  }
}
