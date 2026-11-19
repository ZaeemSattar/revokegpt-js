import { POLICY_LIMITS } from './limits.js';

export type NormalizeResult =
  | { ok: true; path: string; collapsed: string }
  | { ok: false; reason: 'invalid' | 'non-canonical'; detail: string };

const bad = (
  reason: 'invalid' | 'non-canonical',
  detail: string,
): { ok: false; reason: 'invalid' | 'non-canonical'; detail: string } => ({
  ok: false,
  reason,
  detail,
});

function hexVal(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  return -1;
}

const pct = (b: number): string => `%${b.toString(16).toUpperCase().padStart(2, '0')}`;

/** Length of the UTF-8 sequence led by `lead` with its valid second-byte range, or 0 if invalid. */
function utf8Shape(lead: number): { len: number; lo: number; hi: number } | null {
  if (lead >= 0xc2 && lead <= 0xdf) return { len: 2, lo: 0x80, hi: 0xbf };
  if (lead === 0xe0) return { len: 3, lo: 0xa0, hi: 0xbf }; // no overlong
  if (lead === 0xed) return { len: 3, lo: 0x80, hi: 0x9f }; // no surrogates
  if (lead >= 0xe1 && lead <= 0xef) return { len: 3, lo: 0x80, hi: 0xbf };
  if (lead === 0xf0) return { len: 4, lo: 0x90, hi: 0xbf }; // no overlong
  if (lead === 0xf4) return { len: 4, lo: 0x80, hi: 0x8f }; // at most U+10FFFF
  if (lead >= 0xf1 && lead <= 0xf3) return { len: 4, lo: 0x80, hi: 0xbf };
  return null; // stray continuation, C0, C1, F5..FF
}

/** RFC 3986 5.2.4 on a path that starts with "/". Empty segments are kept. */
function removeDotSegments(path: string): string {
  const segs = path.split('/');
  const out: string[] = [];
  let trailing = false;
  for (let i = 1; i < segs.length; i++) {
    const s = segs[i] as string;
    const last = i === segs.length - 1;
    if (s === '.') {
      trailing = last;
    } else if (s === '..') {
      out.pop();
      trailing = last;
    } else {
      out.push(s);
      trailing = false;
    }
  }
  if (trailing) out.push('');
  return `/${out.join('/')}`;
}

function dropTrailingSlash(p: string): string {
  return p.length > 1 && p.endsWith('/') ? p.slice(0, -1) : p;
}

/** Escape bytes that stay encoded (upper-case hex) in the canonical form: `% ? # space [ ] { } | ^ " < >` and backtick. */
const KEEP_ENCODED = new Set<number>([
  0x25, 0x3f, 0x23, 0x20, 0x5b, 0x5d, 0x7b, 0x7d, 0x7c, 0x5e, 0x22, 0x3c, 0x3e, 0x60,
]);

export type SegmentResult =
  | { ok: true; text: string; escaped: boolean }
  | { ok: false; reason: 'invalid' | 'non-canonical'; detail: string };

/**
 * Canonical spelling of one path fragment that holds no "/" (a segment of a request path, or a
 * literal piece of a glob segment between `*`). One function for both, so a rule and a request
 * meet in the same alphabet. Per byte:
 * - a raw printable ASCII character stays, except `[ ] { } | ^ " < >` and backtick and space,
 *   which become upper-case `%XX`; raw `\` is `invalid`, raw `;` is `non-canonical`, a raw
 *   control character or a raw `?` or `#` is `invalid`;
 * - a raw non-ASCII character is `invalid` (`nonAscii: 'invalid'`, requests) or becomes its
 *   upper-case UTF-8 `%XX` bytes (`'encode'`, globs);
 * - an escape `%XX` of printable ASCII is DECODED, except the bytes that stay encoded
 *   (`%25 %3F %23 %20 %5B %5D %7B %7D %7C %5E %22 %3C %3E %60`, upper-cased); `%2F`, `%5C`,
 *   `%3B` and every encoded control are `non-canonical`;
 * - an escape of a byte at or above 0x80 must form valid UTF-8 (no overlong form, surrogate or
 *   value above U+10FFFF), else `non-canonical`; it stays escaped with upper-case hex;
 * - a malformed escape is `invalid`.
 * `escaped` tells whether any escape was present (used for the encoded dot segment rule).
 */
export function decodeSegment(raw: string, nonAscii: 'invalid' | 'encode'): SegmentResult {
  let out = '';
  let escaped = false;
  let i = 0;
  while (i < raw.length) {
    const c = raw.charCodeAt(i);
    if (c === 0x25) {
      const bytes: number[] = [];
      while (i < raw.length && raw.charCodeAt(i) === 0x25) {
        const h = hexVal(raw.charCodeAt(i + 1));
        const l = hexVal(raw.charCodeAt(i + 2));
        if (h < 0 || l < 0) return bad('invalid', 'bad-escape');
        bytes.push(h * 16 + l);
        i += 3;
      }
      escaped = true;
      let k = 0;
      while (k < bytes.length) {
        const b = bytes[k] as number;
        if (b < 0x80) {
          if (b === 0x2f || b === 0x5c) return bad('non-canonical', 'encoded-separator');
          if (b === 0x3b) return bad('non-canonical', 'encoded-semicolon');
          if (b < 0x20 || b === 0x7f) return bad('non-canonical', 'encoded-control');
          out += KEEP_ENCODED.has(b) ? pct(b) : String.fromCharCode(b);
          k++;
        } else {
          const shape = utf8Shape(b);
          if (shape === null || k + shape.len > bytes.length)
            return bad('non-canonical', 'invalid-utf8');
          let t = pct(b);
          for (let j = 1; j < shape.len; j++) {
            const cb = bytes[k + j] as number;
            const lo = j === 1 ? shape.lo : 0x80;
            const hi = j === 1 ? shape.hi : 0xbf;
            if (cb < lo || cb > hi) return bad('non-canonical', 'invalid-utf8');
            t += pct(cb);
          }
          out += t;
          k += shape.len;
        }
      }
      continue;
    }
    if (c === 0x3b) return bad('non-canonical', 'path-parameter');
    if (c === 0x5c) return bad('invalid', 'backslash');
    if (c < 0x20 || c === 0x7f) return bad('invalid', 'control-character');
    if (c === 0x3f || c === 0x23) return bad('invalid', 'reserved-character');
    if (c > 0x7e) {
      if (nonAscii === 'invalid') return bad('invalid', 'non-ascii');
      const cp = raw.codePointAt(i) as number;
      if (cp >= 0xd800 && cp <= 0xdfff) return bad('invalid', 'lone-surrogate');
      for (const byte of new TextEncoder().encode(String.fromCodePoint(cp))) out += pct(byte);
      i += cp > 0xffff ? 2 : 1;
      continue;
    }
    out += KEEP_ENCODED.has(c) ? pct(c) : raw.charAt(i);
    i++;
  }
  return { ok: true, text: out, escaped };
}

/**
 * Normalise a raw request target (origin-form: path and optional query) into the string rules
 * match on (protocol v1, section 18.3). Two forms are returned: `path` keeps repeated slashes
 * after dot-segment removal; `collapsed` merges repeated slashes first and then removes dot
 * segments. They are equal unless the target has `//`. A decision takes the stricter of both.
 *
 * Steps, in order:
 * 1. Not a string, or a raw control character (U+0000-U+001F, U+007F) anywhere: `invalid`.
 * 2. Not origin-form (does not start with "/", so `*` and `http://h/x`): `invalid`.
 * 3. The path is everything before the first `?` or `#`. Over 8 KiB: `non-canonical`.
 * 4. Each segment goes through `decodeSegment` (request mode). A segment that is `.` or `..`
 *    after decoding but was written with an escape (`%2e%2e`, `%2E.`, `.%2e`) is `non-canonical`.
 * 5. Remove dot segments (RFC 3986 5.2.4; `..` above the root is dropped), then drop ONE trailing
 *    slash (the root stays "/").
 */
export function normalizePath(rawTarget: string): NormalizeResult {
  if (typeof rawTarget !== 'string') return bad('invalid', 'not-a-string');
  for (let i = 0; i < rawTarget.length; i++) {
    const c = rawTarget.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return bad('invalid', 'control-character');
  }
  if (rawTarget.charCodeAt(0) !== 0x2f) return bad('invalid', 'not-origin-form');
  let end = rawTarget.length;
  for (let i = 0; i < rawTarget.length; i++) {
    const c = rawTarget.charCodeAt(i);
    if (c === 0x3f || c === 0x23) {
      end = i;
      break;
    }
  }
  const raw = rawTarget.slice(0, end);
  if (raw.length > POLICY_LIMITS.maxRawPathBytes) return bad('non-canonical', 'path-too-long');

  const parts = raw.split('/');
  let decoded = '';
  for (let i = 0; i < parts.length; i++) {
    const r = decodeSegment(parts[i] as string, 'invalid');
    if (!r.ok) return r;
    if ((r.text === '.' || r.text === '..') && r.escaped)
      return bad('non-canonical', 'encoded-dot-segment');
    decoded += i === 0 ? r.text : `/${r.text}`;
  }
  const path = dropTrailingSlash(removeDotSegments(decoded));
  const collapsed = dropTrailingSlash(removeDotSegments(decoded.replace(/\/{2,}/g, '/')));
  return { ok: true, path, collapsed };
}
