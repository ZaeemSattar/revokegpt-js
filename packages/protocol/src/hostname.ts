import { copyRegex, HOSTNAME_FORBIDDEN, HOSTNAME_LABELS } from './patterns.js';
import { decodePunycode } from './punycode.js';

/** Maximum length of a canonical hostname (characters, without a trailing dot). */
export const HOSTNAME_MAX_LENGTH = 253;

/**
 * Label syntax of a canonical hostname: letter-digit-hyphen labels of 1 to 63 characters joined by
 * dots. No lookahead (it compiles in RE2); a canonical hostname ALSO has at most
 * HOSTNAME_MAX_LENGTH characters. The whole string must match; no trailing newline. A public copy:
 * mutating it does not affect validation.
 */
export const CANONICAL_HOSTNAME_RE: RegExp = copyRegex(HOSTNAME_LABELS);

/**
 * Characters that make `canonicalizeHostname` return null before URL parsing. Spelled out so every
 * SDK can copy it exactly (protocol v1, section 3):
 * - whitespace (the ECMAScript `\s` set): U+0009-U+000D, U+0020, U+00A0, U+1680, U+2000-U+200A,
 *   U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF;
 * - C0 controls U+0000-U+001F, DEL U+007F and C1 controls U+0080-U+009F;
 * - the delimiters `/ ? # @ : \ % *`.
 */
export const HOSTNAME_FORBIDDEN_RE: RegExp = copyRegex(HOSTNAME_FORBIDDEN);

/** Length and label syntax of a canonical hostname (no URL parsing). */
function hasCanonicalShape(host: string): boolean {
  return host.length <= HOSTNAME_MAX_LENGTH && HOSTNAME_LABELS.test(host);
}

/**
 * An `xn--` label is accepted only if it is valid punycode that round-trips: the RFC 3492 decoding
 * of the rest of the label succeeds, contains at least one non-ASCII code point, and the URL parser
 * maps the decoded label back to exactly the original label. This rejects labels such as `xn--a`
 * that some URL parsers pass through unchecked, independently of the engine.
 */
function isRoundTripPunycodeLabel(label: string): boolean {
  const decoded = decodePunycode(label.slice(4));
  if (decoded === null || !decoded.some((cp) => cp >= 0x80)) return false;
  try {
    return new URL(`https://${String.fromCodePoint(...decoded)}/`).hostname === label;
  } catch {
    return false;
  }
}

/**
 * Canonicalize a bare hostname via the WHATWG URL parser (lowercase A-labels, IPv4 normalisation),
 * then require the canonical shape (at most HOSTNAME_MAX_LENGTH characters, LDH labels) and valid,
 * round-tripping punycode in every `xn--` label. Returns null for anything that is not a plain
 * canonical hostname. Never throws. IPv6 unsupported.
 */
export function canonicalizeHostname(input: string): string | null {
  if (typeof input !== 'string' || input.length === 0 || HOSTNAME_FORBIDDEN.test(input))
    return null;
  let host: string;
  try {
    host = new URL(`https://${input}/`).hostname;
  } catch {
    return null;
  }
  if (host.endsWith('.')) host = host.slice(0, -1);
  if (!hasCanonicalShape(host)) return null;
  for (const label of host.split('.')) {
    if (label.startsWith('xn--') && !isRoundTripPunycodeLabel(label)) return null;
  }
  return host;
}

/**
 * A last label the URL parser may read as an IPv4 number: all digits, or starting with `0x`
 * (lowercase, as canonical hostnames are). Same rule as the database's `are_hostname_patterns`.
 */
const NUMERIC_LAST_LABEL = /(?:^|\.)(?:[0-9]+|0x[a-z0-9-]*)$/;

/**
 * Canonical exact hostname, or `*.` + canonical hostname with at least 2 labels whose last label
 * is not numeric (not all digits and not starting with `0x`), so `*.1.2.3.4` and `*.a.0xg` are
 * invalid, as in the database (red-team round 2, K-3). An exact canonical dotted quad such as
 * `1.2.3.4` stays valid.
 */
export function isValidHostnamePattern(p: string): boolean {
  if (typeof p !== 'string') return false;
  if (p.startsWith('*.')) {
    const base = p.slice(2);
    return (
      base.includes('.') && canonicalizeHostname(base) === base && !NUMERIC_LAST_LABEL.test(base)
    );
  }
  return canonicalizeHostname(p) === p;
}

/** True if host equals the exact pattern, or is a strict subdomain of a `*.` pattern. */
export function hostnameMatches(host: string, pattern: string): boolean {
  if (!isValidHostnamePattern(pattern)) return false;
  const h = canonicalizeHostname(host);
  if (h === null) return false;
  if (pattern.startsWith('*.')) {
    const base = pattern.slice(2);
    return h !== base && h.endsWith(`.${base}`);
  }
  return h === pattern;
}

/**
 * Allowlist check, fail closed: an empty (or non-array) list matches no hostname, so a site with
 * no allowed hostnames cannot issue challenges. Otherwise true iff any pattern matches.
 */
export function isHostnameAllowed(host: string, patterns: readonly string[]): boolean {
  if (!Array.isArray(patterns) || patterns.length === 0) return false;
  for (let i = 0; i < patterns.length; i++) {
    if (hostnameMatches(host, patterns[i] as string)) return true;
  }
  return false;
}
