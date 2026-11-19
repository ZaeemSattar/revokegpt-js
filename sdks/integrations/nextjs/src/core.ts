import {
  createFirewall,
  type FirewallConfig,
  type FwRequest,
  type FwResult,
} from '@revokegpt/firewall';
import { type NextRequest, NextResponse } from 'next/server';

export type { FirewallConfig };

/** `integration` defaults to the adapter's own name. */
export type NextConfig = Omit<FirewallConfig, 'integration'> & { integration?: string };

export interface WithRevokeGPTOptions {
  /**
   * Set when next.config has `skipProxyUrlNormalize` (Next 16) / `skipMiddlewareUrlNormalize` (15).
   * Next then leaves its RSC suffixes on the URL; for requests that carry Next's RSC/prefetch request
   * headers the adapter evaluates `/x.prefetch` and `/x.segments/...` as `/x`. Default false.
   */
  skipUrlNormalize?: boolean;
  /**
   * Honour `X-Forwarded-Proto` (http or https) when a relative redirect must be made absolute. Set it
   * only behind a proxy that overwrites that header. Default false: the scheme is `https`.
   */
  trustProxy?: boolean;
  /**
   * Builds the response for a request that passed. `headers` are the request headers with every
   * `x-rg-*` removed and the decision headers set. Default: `NextResponse.next({ request: { headers } })`.
   * A reverse proxy to another origin returns `NextResponse.rewrite(url, { request: { headers } })`.
   */
  pass?: (headers: Headers, req: NextRequest) => NextResponse;
}

/**
 * The documented matcher: everything except Next's immutable build output. It deliberately keeps
 * `/_next/data/*` (page data), Server Function POSTs (they go to the page URL), `/__rg/*` and
 * every API route inside the firewall. Copy the literal into `export const config` (Next reads
 * it statically, so it cannot be imported).
 */
export const MATCHER = '/((?!_next/static|_next/image|favicon.ico).*)';

const MAX_BODY = 4096;
const DATA_ROUTE = /^\/_next\/data\/[^/]+(\/.*)\.json$/;

/** First occurrence of a cookie name wins. */
function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const part of (header ?? '').split(';')) {
    const eq = part.indexOf('=');
    if (eq < 1) continue;
    const name = part.slice(0, eq).trim();
    if (name !== '' && !(name in out)) out[name] = part.slice(eq + 1).trim();
  }
  return out;
}

/**
 * The request target the rules are matched against. Next gives a parsed `nextUrl`; with the default
 * normalisation Next has already stripped `/_next/data/<build>` and `.json`, with
 * `skipProxyUrlNormalize` (Next 16; `skipMiddlewareUrlNormalize` in 15) it is the URL as received.
 * Either way a page-data request is evaluated as the page it belongs to, so a rule for `/admin`
 * also covers `/_next/data/<build>/admin.json`.
 */
export function rawTargetOf(req: NextRequest, skipUrlNormalize = false): string {
  let path = req.nextUrl.pathname;
  const m = DATA_ROUTE.exec(path);
  if (m !== null) path = m[1] === '/index' ? '/' : (m[1] as string);
  // With skipProxyUrlNormalize Next leaves its internal RSC suffixes on the URL (it already strips a
  // trailing `.rsc`): `/admin.prefetch.rsc` arrives as `/admin.prefetch` and a segment prefetch as
  // `/admin.segments/<segment>.segment`. Next serves the page `/admin` for both.
  // Only for requests Next itself marks as RSC/prefetch, so a real route named `x.prefetch` is itself.
  if (skipUrlNormalize && isRscRequest(req)) {
    const seg = path.indexOf('.segments/');
    if (seg > 0) path = path.slice(0, seg);
    else if (path.endsWith('.prefetch') && path.length > '.prefetch'.length)
      path = path.slice(0, -'.prefetch'.length);
  }
  if (path === '') path = '/';
  return path + req.nextUrl.search;
}

function isRscRequest(req: NextRequest): boolean {
  const h = req.headers;
  return (
    h.get('rsc') === '1' ||
    h.get('next-router-prefetch') !== null ||
    h.get('next-router-segment-prefetch') !== null
  );
}

/** `x-matched-path` is set by Next/platform adapters, never by a visitor; one naming the reserved namespace is refused. */
function matchedPathIsReserved(req: NextRequest): boolean {
  const v = req.headers.get('x-matched-path');
  if (v === null) return false;
  const p = v.split(/[?#]/)[0] ?? '';
  const l = p.toLowerCase().replace(/%5f/g, '_').replace(/%2f/g, '/');
  return l === '/__rg' || l.startsWith('/__rg/');
}

async function readCapped(req: NextRequest): Promise<string> {
  if (req.body === null) return '';
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.length;
    if (size > MAX_BODY) {
      await reader.cancel();
      break;
    }
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.length;
  }
  return new TextDecoder('latin1').decode(all);
}

export function toFwRequest(
  req: NextRequest,
  skipUrlNormalize = false,
  waitUntil?: (p: Promise<unknown>) => void,
): FwRequest {
  return {
    method: req.method,
    host: req.headers.get('host') ?? req.nextUrl.host,
    rawTarget: rawTargetOf(req, skipUrlNormalize),
    headers: [...req.headers.entries()],
    cookies: parseCookies(req.headers.get('cookie')),
    body: () => readCapped(req),
    ...(waitUntil === undefined ? {} : { waitUntil }),
  };
}

/**
 * The origin used for an absolute Location: the request's Host (the host the firewall decided on)
 * and the request scheme, never the server's internal origin (`req.nextUrl.origin` can be
 * `localhost:3000` behind a proxy). Scheme: https, or X-Forwarded-Proto when `trustProxy` is set.
 */
export function originOf(req: NextRequest, opts: WithRevokeGPTOptions = {}): string {
  let proto = 'https';
  if (opts.trustProxy === true) {
    const f = req.headers.get('x-forwarded-proto')?.split(',')[0]?.trim().toLowerCase();
    if (f === 'http' || f === 'https') proto = f;
  }
  try {
    const host = req.headers.get('host');
    if (host !== null && host !== '') return new URL(`${proto}://${host}`).origin;
  } catch {
    // malformed Host: fall through
  }
  return `${proto}://${req.nextUrl.host}`;
}

/**
 * Next's adapter parses a response `Location` with `new NextURL(location)` and no base, so a
 * relative one throws (a 500). A same-site path is made absolute against the request's own origin.
 */
function respond(r: Extract<FwResult, { type: 'respond' }>, origin: string): NextResponse {
  const headers = new Headers();
  for (const [n, v] of r.headers)
    headers.append(
      n,
      n.toLowerCase() === 'location' && v.startsWith('/') && !v.startsWith('//')
        ? new URL(v, origin).href
        : v,
    );
  return new NextResponse(r.status === 204 ? null : r.body, { status: r.status, headers });
}

/**
 * The firewall as a Next.js proxy/middleware function. Node runtime only: it uses the Node
 * `fetch`, WebCrypto and timers the core needs, and keeps the bundle cache in module memory.
 */
export function withRevokeGPT(
  cfg: NextConfig,
  opts: WithRevokeGPTOptions = {},
): (
  req: NextRequest,
  event?: { waitUntil?: (p: Promise<unknown>) => void },
) => Promise<NextResponse> {
  const fw = createFirewall({ integration: 'nextjs/0.0.0', ...cfg });
  return async (req, event) => {
    if (matchedPathIsReserved(req)) return respond(notFound(), originOf(req, opts));
    const out = await fw.handle(
      toFwRequest(
        req,
        opts.skipUrlNormalize === true,
        typeof event?.waitUntil === 'function' ? (p) => event.waitUntil?.(p) : undefined,
      ),
    );
    if (out.type === 'respond') return respond(out, originOf(req, opts));
    const headers = new Headers(req.headers);
    for (const n of out.stripHeaders) headers.delete(n);
    for (const [n, v] of Object.entries(out.setHeaders)) headers.set(n, v);
    return opts.pass?.(headers, req) ?? NextResponse.next({ request: { headers } });
  };
}

function notFound(): Extract<FwResult, { type: 'respond' }> {
  return {
    type: 'respond',
    status: 404,
    headers: [
      ['Cache-Control', 'no-store'],
      ['Vary', 'Cookie'],
      ['Content-Type', 'text/plain; charset=utf-8'],
      ['X-Content-Type-Options', 'nosniff'],
    ],
    body: 'Not Found',
  };
}
