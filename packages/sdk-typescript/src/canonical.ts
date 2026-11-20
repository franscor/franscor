/**
 * Canonical JSON — byte-identical to the Python SDK (`franscor.canonical`):
 * keys sorted by code point, no whitespace, UTF-8 unescaped, numbers in
 * ECMAScript shortest form, unsafe integers / NaN / Infinity rejected.
 */
import { createHash } from 'node:crypto';

export class CanonicalError extends Error {
  override name = 'CanonicalError';
}

function compareCodePoints(a: string, b: string): number {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const x = ia.next();
    const y = ib.next();
    if (x.done) return y.done ? 0 : -1;
    if (y.done) return 1;
    const cx = x.value.codePointAt(0)!;
    const cy = y.value.codePointAt(0)!;
    if (cx !== cy) return cx - cy;
  }
}

function encode(value: unknown, path: string, out: string[]): void {
  if (value === null) {
    out.push('null');
  } else if (typeof value === 'boolean') {
    out.push(value ? 'true' : 'false');
  } else if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new CanonicalError(`${path}: ${value} has no JSON representation`);
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new CanonicalError(`${path}: integral number ${value} exceeds 2^53-1; use a string`);
    }
    out.push(Object.is(value, -0) ? '0' : String(value));
  } else if (typeof value === 'bigint') {
    throw new CanonicalError(`${path}: bigint is not portable JSON; use a string`);
  } else if (typeof value === 'string') {
    out.push(JSON.stringify(value));
  } else if (Array.isArray(value)) {
    out.push('[');
    value.forEach((item, i) => {
      if (i) out.push(',');
      encode(item === undefined ? null : item, `${path}[${i}]`, out);
    });
    out.push(']');
  } else if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort(compareCodePoints);
    out.push('{');
    keys.forEach((key, i) => {
      if (i) out.push(',');
      out.push(JSON.stringify(key), ':');
      encode(obj[key], `${path}.${key}`, out);
    });
    out.push('}');
  } else {
    throw new CanonicalError(`${path}: ${typeof value} is not JSON`);
  }
}

export function canonicalJson(value: unknown): string {
  const out: string[] = [];
  encode(value, '$', out);
  return out.join('');
}

export function sha256Hex(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

export function canonicalHash(value: unknown): string {
  return sha256Hex(Buffer.from(canonicalJson(value), 'utf8'));
}

export const b64 = (raw: Uint8Array): string => Buffer.from(raw).toString('base64url');
export const unb64 = (text: string): Buffer => Buffer.from(text, 'base64url');
