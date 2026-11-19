import { POLICY_LIMITS } from './limits.js';
import { decodeSegment } from './normalize.js';

/** A compiled path glob: segments, each `**` (zero or more whole segments) or a segment pattern. */
export interface Glob {
  readonly source: string;
  /** The rule in canonical spelling (trailing slash dropped, literals through `decodeSegment`). */
  readonly canonical: string;
  readonly segments: readonly (string | null)[]; // null is `**`; otherwise a segment pattern (may hold `*`)
}

/**
 * Compile a path glob, or return null if it is not valid (protocol v1, section 18.2). Grammar:
 * starts with "/"; segments of literal characters and `*` (matches within one segment, any
 * number of characters, possibly none); a segment that is exactly `**` matches zero or more whole
 * segments. Nothing else: no `?`, classes, alternation or regex. At most 200 characters and 8
 * wildcards. Every literal piece (the text between `*`) goes through `decodeSegment` in glob mode,
 * the same function that canonicalises request paths, so a rule is stored in the canonical
 * spelling: `/a:b`, `/a%3Ab` and `/a%3ab` are one rule, `/caf\u00e9` and `/caf%C3%A9` are one rule,
 * `/a[b` and `/a%5Bb` are one rule. Refused (null): `%2F`, `%5C`, `%3B`, an encoded control, bad
 * UTF-8, a malformed escape, a raw `\`, `;`, `?` or `#`, a raw control character, an escape that
 * would decode to `*` (`%2A`), empty segments (`//`), and dot segments (written with or without
 * escapes). One trailing slash is ignored; `/` alone is the root.
 */
export function compileGlob(p: string): Glob | null {
  if (typeof p !== 'string' || p.length === 0 || p.length > POLICY_LIMITS.maxGlobLength)
    return null;
  if (p.charCodeAt(0) !== 0x2f) return null;
  const body = p.length > 1 && p.endsWith('/') ? p.slice(0, -1) : p;
  if (body === '/') return { source: p, canonical: '/', segments: [] };
  const segments: (string | null)[] = [];
  let wildcards = 0;
  for (const s of body.slice(1).split('/')) {
    if (s === '') return null;
    if (s === '**') {
      wildcards++;
      segments.push(null);
      continue;
    }
    if (s.includes('**')) return null;
    const pieces = s.split('*');
    wildcards += pieces.length - 1;
    const canon: string[] = [];
    for (const piece of pieces) {
      if (piece === '') {
        canon.push('');
        continue;
      }
      const r = decodeSegment(piece, 'encode');
      if (!r.ok || r.text.includes('*')) return null;
      canon.push(r.text);
    }
    const seg = canon.join('*');
    if (seg === '.' || seg === '..') return null;
    segments.push(seg);
  }
  if (wildcards > POLICY_LIMITS.maxWildcards) return null;
  return {
    source: p,
    canonical: `/${segments.map((x) => (x === null ? '**' : x)).join('/')}`,
    segments,
  };
}

/** Match one segment against a pattern whose only metacharacter is `*`. */
function segmentMatches(p: string, s: string): boolean {
  let pi = 0;
  let si = 0;
  let star = -1;
  let mark = 0;
  while (si < s.length) {
    if (pi < p.length && p.charCodeAt(pi) === 0x2a) {
      star = pi++;
      mark = si;
    } else if (pi < p.length && p.charCodeAt(pi) === s.charCodeAt(si)) {
      pi++;
      si++;
    } else if (star >= 0) {
      pi = star + 1;
      si = ++mark;
    } else {
      return false;
    }
  }
  while (pi < p.length && p.charCodeAt(pi) === 0x2a) pi++;
  return pi === p.length;
}

/**
 * Match a normalised path (starting with "/") against a compiled glob. No recursion.
 *
 * Cost: no recursion and no exponential case. Matching works on path segments with one saved
 * restart point for the last `**` (`starP`, `starS`) and, inside a segment, one saved restart point
 * for the last `*`. A segment pattern is matched against one whole path segment, a pure function
 * of the pair. After a mismatch the saved `**` swallows exactly one more path segment (`starS`
 * only increases, at most N times) and the pattern after it is retried from its start: at most P
 * segment comparisons per retry, each O(segment length x pattern length) in the worst case. The
 * bound is O(N x P x L), polynomial and small at the limits (path 8 KiB, pattern 200 characters,
 * 8 wildcards); it is not linear. Greedy leftmost matching of the blocks between `**` is optimal,
 * so a later `**` replaces the saved point for good. The vectors keep a 5 ms budget on the
 * pathological cases.
 */
export function globMatch(g: Glob, path: string): boolean {
  if (typeof path !== 'string' || path.charCodeAt(0) !== 0x2f) return false;
  const ps = path === '/' ? [] : path.slice(1).split('/');
  const segs = g.segments;
  const m = segs.length;
  const n = ps.length;
  let pi = 0;
  let si = 0;
  let starP = -1;
  let starS = 0;
  while (si < n) {
    const gs = pi < m ? (segs[pi] as string | null) : undefined;
    if (gs === null) {
      starP = pi++;
      starS = si;
    } else if (gs !== undefined && segmentMatches(gs, ps[si] as string)) {
      pi++;
      si++;
    } else if (starP >= 0) {
      pi = starP + 1;
      si = ++starS;
    } else {
      return false;
    }
  }
  while (pi < m && segs[pi] === null) pi++;
  return pi === m;
}
