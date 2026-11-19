import { canonicalizeHostname, hostnameMatches } from '../hostname.js';

/**
 * The canonical host of a request: the Host header (or URL authority) with an optional `:port`
 * removed, then `canonicalizeHostname`. Null for anything else (IPv6 literals, userinfo, empty).
 */
export function requestHost(host: string): string | null {
  if (typeof host !== 'string') return null;
  const m = /^([^:]*)(?::([0-9]{1,5}))?$/.exec(host);
  if (m === null || (m[2] !== undefined && Number(m[2]) > 65535)) return null;
  return canonicalizeHostname(m[1] as string);
}

/**
 * A rule host pattern (exact canonical host or `*.example.com`, never the apex) against a request
 * host. A port in the request host is stripped first. Reuses `hostnameMatches`.
 */
export function hostMatches(pattern: string, host: string): boolean {
  const h = requestHost(host);
  return h !== null && hostnameMatches(h, pattern);
}
