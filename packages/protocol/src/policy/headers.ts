import { POLICY_LIMITS } from './limits.js';

/**
 * Names (from an incoming header list) to delete on ingress: every name that, case-insensitively
 * and with `_` read as `-`, starts with `x-rg-`. That covers duplicates (each occurrence is
 * returned), `X_RG_Score` (which CGI, WSGI and PHP map to the same variable as `X-RG-Score`) and
 * the bare prefix `x-rg-`. `x-rgx` is kept. Order and spelling of the input are preserved.
 */
export function stripRgHeaders(names: string[]): string[] {
  return names.filter(
    (n) => typeof n === 'string' && n.toLowerCase().replace(/_/g, '-').startsWith('x-rg-'),
  );
}

/** `X-RG-Score` value: the score floored to a multiple of 10 on 0-100 as a string; NaN, infinities and negatives give "0". */
export function scoreBucket(score: number): string {
  if (typeof score !== 'number' || !Number.isFinite(score) || score <= 0) return '0';
  if (score >= 1) return '100';
  return String(Math.floor(Math.round(score * 1e6) / 1e5) * 10);
}

/**
 * True if `p` is safe to use as a return path (`__Host-rg_r`, `Location` after `/__rg/return`):
 * a relative path that starts with a single "/", has no backslash, space, control or non-ASCII
 * character, no `//` and no dot segment in its path part, no encoded `/`, `\` or control in the
 * path part (and no encoded control anywhere), is at most 2048 characters, and does not point
 * into `/__rg/`. Anything else lands on "/".
 */
export function isSafeReturnPath(p: string): boolean {
  if (typeof p !== 'string' || p.length === 0 || p.length > POLICY_LIMITS.maxReturnPathLength)
    return false;
  if (p.charCodeAt(0) !== 0x2f || p.charCodeAt(1) === 0x2f || p.charCodeAt(1) === 0x5c)
    return false;
  for (let i = 0; i < p.length; i++) {
    const c = p.charCodeAt(i);
    if (c <= 0x20 || c >= 0x7f || c === 0x5c) return false;
  }
  if (/%(?:[01][0-9A-Fa-f]|7[Ff])/.test(p)) return false;
  const q = p.search(/[?#]/);
  const path = q < 0 ? p : p.slice(0, q);
  if (/%(?:2[Ff]|5[Cc])/.test(path) || path.includes('//')) return false;
  if (/(?:^|\/)(?:\.|%2[Ee]){1,2}(?:\/|$)/.test(path)) return false;
  return !(path === '/__rg' || path.startsWith('/__rg/'));
}
