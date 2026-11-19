import { BASE64URL, copyRegex } from './patterns.js';

/**
 * Unpadded base64url alphabet, one or more characters (shape check only; see fromBase64Url).
 * A public copy: mutating it does not affect validation.
 */
export const BASE64URL_RE: RegExp = copyRegex(BASE64URL);

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
/**
 * Char code (0..127) to 6-bit value, -1 for characters outside the alphabet. A typed array, so a
 * polluted `Object.prototype` can never add "alphabet" characters.
 */
const REVERSE: Int8Array = (() => {
  const t = new Int8Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) t[ALPHABET.charCodeAt(i)] = i;
  return t;
})();

/** Base64url encoding without padding. */
export function toBase64Url(b: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const n = ((b[i] as number) << 16) | ((b[i + 1] as number) << 8) | (b[i + 2] as number);
    out +=
      ALPHABET.charAt((n >> 18) & 63) +
      ALPHABET.charAt((n >> 12) & 63) +
      ALPHABET.charAt((n >> 6) & 63) +
      ALPHABET.charAt(n & 63);
  }
  const rem = b.length - i;
  if (rem === 1) {
    const n = (b[i] as number) << 16;
    out += ALPHABET.charAt((n >> 18) & 63) + ALPHABET.charAt((n >> 12) & 63);
  } else if (rem === 2) {
    const n = ((b[i] as number) << 16) | ((b[i + 1] as number) << 8);
    out +=
      ALPHABET.charAt((n >> 18) & 63) +
      ALPHABET.charAt((n >> 12) & 63) +
      ALPHABET.charAt((n >> 6) & 63);
  }
  return out;
}

/** Strict unpadded base64url decoder. Throws TypeError on invalid characters or length. */
export function fromBase64Url(s: string): Uint8Array {
  if (typeof s !== 'string') throw new TypeError('base64url input must be a string');
  if (s.length % 4 === 1) throw new TypeError('invalid base64url length');
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? (REVERSE[c] as number) : -1;
    if (v < 0) throw new TypeError('invalid base64url character');
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
      acc &= (1 << bits) - 1;
    }
  }
  if (acc !== 0) throw new TypeError('non-canonical base64url');
  return out;
}
