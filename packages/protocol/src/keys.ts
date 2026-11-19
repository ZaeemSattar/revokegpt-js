import { BASE62_ALPHABET, randomBase62 } from './base62.js';
import { crc32 } from './crc32.js';
import { copyRegex, SECRET_KEY, SITE_KEY } from './patterns.js';
import { timingSafeEqual } from './timing.js';

// Public copies; validation uses the private instances in src/patterns.ts.
export const SITE_KEY_RE: RegExp = copyRegex(SITE_KEY);
export const SECRET_KEY_RE: RegExp = copyRegex(SECRET_KEY);

export type SecretKeyKind = 'secret' | 'management';

export const SITE_KEY_PREFIX = 'rgpk';
export const SECRET_KEY_PREFIX = 'rgsk';
export const MANAGEMENT_KEY_PREFIX = 'rgmk';
/** Versioned domain-separation prefix for secret-key HMAC input. */
export const KEY_HASH_DOMAIN = 'rg-key-hash-v1:';

/**
 * The closed vocabulary of management-key scopes (protocol v1 section 2). Scopes are set when a
 * key is minted and never change; any other string is rejected. The database enforces the same
 * list (`api_keys_scopes_vocabulary` in the database migrations).
 */
export const MANAGEMENT_SCOPES = Object.freeze([
  'sites:read',
  'sites:write',
  'secrets:rotate',
  'audit:read',
] as const);
export type ManagementScope = (typeof MANAGEMENT_SCOPES)[number];

function prefixFor(kind: SecretKeyKind): string {
  if (kind === 'secret') return SECRET_KEY_PREFIX;
  if (kind === 'management') return MANAGEMENT_KEY_PREFIX;
  throw new TypeError('unknown secret key kind');
}
const HEX64_RE = /^[0-9a-f]{64}$/;
const MIN_PEPPER_BYTES = 32;
const encoder = new TextEncoder();

export function isSiteKey(s: string): boolean {
  return typeof s === 'string' && SITE_KEY.test(s);
}

export function generateSiteKey(): string {
  return `${SITE_KEY_PREFIX}_${randomBase62(20)}`;
}

/** CRC32 of the UTF-8 body as 6 base62 digits, most significant first, zero-padded. */
export function keyChecksum(body: string): string {
  let n = crc32(encoder.encode(body));
  let out = '';
  for (let i = 0; i < 6; i++) {
    out = BASE62_ALPHABET.charAt(n % 62) + out;
    n = Math.floor(n / 62);
  }
  return out;
}

/** Throws TypeError for any kind other than `'secret'` or `'management'`. */
export function generateSecretKey(kind: SecretKeyKind): { key: string; keyId: string } {
  const prefix = prefixFor(kind);
  const keyId = randomBase62(12);
  const body = `${prefix}_${keyId}_${randomBase62(32)}`;
  return { key: body + keyChecksum(body), keyId };
}

/** Returns null (never throws) unless the format matches and the checksum verifies. */
export function parseSecretKey(s: string): { kind: SecretKeyKind; keyId: string } | null {
  if (typeof s !== 'string') return null;
  const m = SECRET_KEY.exec(s);
  if (!m) return null;
  const checksum = m[4] as string;
  const body = s.slice(0, s.length - checksum.length);
  if (!timingSafeEqual(encoder.encode(keyChecksum(body)), encoder.encode(checksum))) return null;
  return { kind: m[1] === SECRET_KEY_PREFIX ? 'secret' : 'management', keyId: m[2] as string };
}

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * True if `s` has no lone surrogates: the same result as ES2024 `String.prototype.isWellFormed`,
 * written out so it does not depend on the runtime or on a patched prototype.
 */
function isWellFormedUtf16(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1); // NaN past the end
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/**
 * Copies the pepper, then checks the copy. `new Uint8Array(view)` copies by the view's internal
 * length, so a subclass that lies through a `length` getter cannot pass the size check, and later
 * mutation of the caller's array cannot change the key being imported.
 */
function copyPepper(pepper: unknown): Uint8Array<ArrayBuffer> {
  if (!(pepper instanceof Uint8Array)) throw new TypeError('pepper must be a Uint8Array');
  const copy = new Uint8Array(pepper);
  if (copy.byteLength < MIN_PEPPER_BYTES) {
    throw new RangeError(`pepper must be at least ${MIN_PEPPER_BYTES} bytes`);
  }
  return copy;
}

async function hmacHex(key: string, pepper: Uint8Array<ArrayBuffer>): Promise<string> {
  const k = await globalThis.crypto.subtle.importKey(
    'raw',
    pepper,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await globalThis.crypto.subtle.sign('HMAC', k, encoder.encode(KEY_HASH_DOMAIN + key));
  return toHex(new Uint8Array(mac));
}

/**
 * Lowercase hex HMAC-SHA-256(pepper, UTF-8("rg-key-hash-v1:" + key)). The pepper must be a
 * Uint8Array of at least 32 bytes (RangeError otherwise; TypeError if it is not a Uint8Array). The
 * key must be a well-formed string: a non-string or a string with a lone surrogate (which UTF-8
 * encoding would silently turn into U+FFFD) throws TypeError.
 */
export async function hashSecret(key: string, pepper: Uint8Array): Promise<string> {
  const p = copyPepper(pepper);
  if (typeof key !== 'string') throw new TypeError('key must be a string');
  if (!isWellFormedUtf16(key)) throw new TypeError('key must not contain lone surrogates');
  return hmacHex(key, p);
}

/**
 * Constant-time check of `key` against a stored lowercase hex hash. Returns false (never throws) for
 * any bad key or stored hash: a non-string key, a key with a lone surrogate, or a stored value that
 * is not 64 lowercase hex characters. A bad pepper is a server misconfiguration and throws, as in
 * hashSecret.
 */
export async function verifySecretHash(
  key: string,
  storedHex: string,
  pepper: Uint8Array,
): Promise<boolean> {
  const p = copyPepper(pepper);
  if (typeof key !== 'string' || !isWellFormedUtf16(key)) return false;
  if (typeof storedHex !== 'string' || !HEX64_RE.test(storedHex)) return false;
  const actual = fromHex(await hmacHex(key, p));
  return timingSafeEqual(actual, fromHex(storedHex));
}
