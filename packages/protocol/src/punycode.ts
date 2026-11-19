// Internal module (not re-exported from src/index.ts): a bounded RFC 3492 Punycode decoder, used
// by canonicalizeHostname to reject `xn--` labels that are not valid punycode. Hand-written to keep
// the package dependency-free (zod is its only runtime dependency).

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 0x80;
/** Arithmetic bound, as in the RFC's reference implementation (fail on overflow, never wrap). */
const MAX_INT = 0x7fffffff;
/** Longest encoded input accepted. A DNS label is at most 63 characters, so 63 bounds all work. */
export const PUNYCODE_MAX_INPUT = 63;

/** Value of a base-36 digit (`a`-`z`/`A`-`Z` are 0-25, `0`-`9` are 26-35), or BASE if invalid. */
function digitValue(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 0x30 + 26;
  if (c >= 0x41 && c <= 0x5a) return c - 0x41;
  if (c >= 0x61 && c <= 0x7a) return c - 0x61;
  return BASE;
}

/** Bias adaptation, RFC 3492 section 6.1. */
function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  let d = firstTime ? Math.floor(delta / DAMP) : Math.floor(delta / 2);
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > Math.floor(((BASE - TMIN) * TMAX) / 2)) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
}

/**
 * Decodes the Punycode string `input` (the part of an ACE label after `xn--`) into code points,
 * following RFC 3492 section 6.2. Returns null (never throws) when the input is longer than
 * PUNYCODE_MAX_INPUT, has a non-ASCII basic code point, an invalid or truncated digit sequence, an
 * arithmetic overflow, or decodes to a value that is not a Unicode scalar value (above U+10FFFF or
 * a surrogate). Work is linear in the (bounded) input length.
 */
export function decodePunycode(input: string): number[] | null {
  if (typeof input !== 'string' || input.length > PUNYCODE_MAX_INPUT) return null;
  // Basic code points: everything before the last delimiter, if there is one.
  const delimiter = input.lastIndexOf('-');
  const basic = Math.max(delimiter, 0);
  const output: number[] = [];
  for (let j = 0; j < basic; j++) {
    const c = input.charCodeAt(j);
    if (c >= 0x80) return null;
    output.push(c);
  }
  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;
  // Deltas start after the last delimiter if any basic code points were copied, else at 0.
  let pos = basic > 0 ? basic + 1 : 0;
  while (pos < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (pos >= input.length) return null; // truncated variable-length integer
      const digit = digitValue(input.charCodeAt(pos++));
      if (digit >= BASE) return null;
      if (digit > Math.floor((MAX_INT - i) / w)) return null;
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      if (w > Math.floor(MAX_INT / (BASE - t))) return null;
      w *= BASE - t;
    }
    const length = output.length + 1;
    bias = adapt(i - oldi, length, oldi === 0);
    if (Math.floor(i / length) > MAX_INT - n) return null;
    n += Math.floor(i / length);
    i %= length;
    if (n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) return null;
    output.splice(i, 0, n);
    i++;
  }
  return output;
}
