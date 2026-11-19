export const BASE62_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

/** Largest multiple of 62 that fits in a byte; bytes at or above it are discarded (no modulo bias). */
const REJECT_AT = 248;

/** Largest length randomBase62 produces in one call. */
const MAX_LENGTH = 4096;

/**
 * Cryptographically random base62 string using rejection sampling (bytes >= 248 discarded).
 * `length` must be an integer from 0 to 4096 (RangeError otherwise).
 */
export function randomBase62(length: number): string {
  if (!Number.isInteger(length) || length < 0 || length > MAX_LENGTH)
    throw new RangeError(`length must be an integer from 0 to ${MAX_LENGTH}`);
  let out = '';
  while (out.length < length) {
    const need = length - out.length;
    // Oversample so one batch almost always suffices (acceptance rate is 248/256).
    const buf = new Uint8Array(Math.min(4096, Math.max(16, Math.ceil(need * 1.2) + 8)));
    globalThis.crypto.getRandomValues(buf);
    for (let i = 0; i < buf.length && out.length < length; i++) {
      const b = buf[i] as number;
      if (b < REJECT_AT) out += BASE62_ALPHABET.charAt(b % 62);
    }
  }
  return out;
}
