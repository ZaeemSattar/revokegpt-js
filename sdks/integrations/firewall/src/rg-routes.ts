import {
  fromBase64Url,
  type PolicyBundlePayload,
  isSafeReturnPath as protocolSafeReturnPath,
  verifySession,
} from '@revokegpt/protocol';
import {
  COOKIE_CLEARANCE,
  COOKIE_RETURN,
  COOKIE_SESSION,
  clearCookie,
  setCookie,
} from './cookies.js';

/** `isSafeReturnPath` plus: no encoded spelling of the reserved `/__rg` namespace (`/%5f%5frg/...`, `/__RG`). */
export function isSafeReturnPath(p: string): boolean {
  if (!protocolSafeReturnPath(p)) return false;
  const q = p.search(/[?#]/);
  let path = q < 0 ? p : p.slice(0, q);
  for (let i = 0; i < 3; i++) {
    const l = path.toLowerCase().replace(/%5f/g, '_').replace(/%2f/g, '/');
    if (l === '/__rg' || l.startsWith('/__rg/')) return false;
    try {
      const d = decodeURIComponent(path);
      if (d === path) break;
      path = d;
    } catch {
      break;
    }
  }
  return true;
}

export interface FwRequest {
  method: string;
  /** The Host header (a port is stripped by the engine). */
  host: string;
  /** The raw request target (origin-form) before any framework rewriting, query string included. */
  rawTarget: string;
  /** Every request header, in order and with duplicates, names as received. */
  headers: [string, string][];
  cookies: Record<string, string>;
  /**
   * Reads the request body as text. Called ONLY for `POST /__rg/return` (a urlencoded body of at
   * most 4 KiB with the field `rg_clearance`). Everywhere else the action token comes only from
   * the `X-RG-Token` header and the body is never touched. An adapter should bound what it reads.
   */
  body?: () => Promise<string>;
  /** The runtime's `waitUntil` (Workers, Compute): keeps a background bundle refresh alive past the response. */
  waitUntil?: (p: Promise<unknown>) => void;
}

export type FwResult =
  | { type: 'pass'; stripHeaders: string[]; setHeaders: Record<string, string> }
  | { type: 'respond'; status: number; headers: [string, string][]; body: string };

const TEXT: Record<number, string> = {
  204: '',
  303: 'See Other',
  400: 'Bad Request',
  403: 'Forbidden',
  404: 'Not Found',
  405: 'Method Not Allowed',
  413: 'Payload Too Large',
  415: 'Unsupported Media Type',
  429: 'Too Many Requests',
  503: 'Service Unavailable',
};

/** A response from the integration: always `Cache-Control: no-store` and `Vary: Cookie`. */
export function respond(
  status: number,
  extra: [string, string][] = [],
  body?: string,
): Extract<FwResult, { type: 'respond' }> {
  const text = body ?? TEXT[status] ?? '';
  return {
    type: 'respond',
    status,
    headers: [
      ['Cache-Control', 'no-store'],
      ['Vary', 'Cookie'],
      ['Content-Type', 'text/plain; charset=utf-8'],
      ['X-Content-Type-Options', 'nosniff'],
      ...extra,
    ],
    body: text,
  };
}

export const header = (req: FwRequest, name: string): string[] =>
  req.headers.filter(([n]) => n.toLowerCase() === name).map(([, v]) => v);

const encoder = new TextEncoder();
const MAX_FORM_BYTES = 4096;

/** `exp` of an already verified token. */
function expOf(token: string): number {
  const parts = token.split('.');
  const claims = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[2] as string))) as {
    exp: number;
  };
  return claims.exp;
}

function maxAge(token: string, now: number, cap: number): number {
  return Math.max(0, Math.min(expOf(token) - now, cap));
}

const bundleOf = (b: PolicyBundlePayload) => ({ minIat: b.minIat, revokedJti: b.revokedJti });

/** `POST /__rg/session`: the session token in `X-RG-Session-Init` becomes the `__Host-rg_s` cookie. */
export async function handleSession(
  req: FwRequest,
  b: PolicyBundlePayload,
  nowSec: number,
): Promise<FwResult> {
  if (req.method !== 'POST') return respond(405, [['Allow', 'POST']]);
  const init = header(req, 'x-rg-session-init');
  if (init.length !== 1 || init[0] === '') return respond(400);
  const token = init[0] as string;
  const s = await verifySession(
    token,
    b.tokenKeys,
    { siteId: b.siteId, host: req.host },
    bundleOf(b),
    nowSec,
  );
  if (s.kind !== 'valid' || s.lvl !== 0) return respond(400);
  const cookie = setCookie(COOKIE_SESSION, token, maxAge(token, nowSec, b.session.ttl));
  if (cookie === null) return respond(400);
  return respond(204, [['Set-Cookie', cookie]]);
}

/**
 * `POST /__rg/return`: the challenge page hands over the clearance. A clearance for this host sets
 * `__Host-rg_c`, clears `__Host-rg_r` and answers 303 to the return path when `isSafeReturnPath`
 * accepts it, else to `/`. This is the only place a request body is read.
 */
export async function handleReturn(
  req: FwRequest,
  b: PolicyBundlePayload,
  nowSec: number,
): Promise<FwResult> {
  if (req.method !== 'POST') return respond(405, [['Allow', 'POST']]);
  // The challenge page posts from the challenge origin; a cross-site form post is refused.
  const origin = header(req, 'origin');
  if (origin.length > 1 || (origin.length === 1 && origin[0] !== b.challengeBase))
    return respond(403);
  const ct = header(req, 'content-type');
  if (ct.length !== 1 || !/^application\/x-www-form-urlencoded\s*(;.*)?$/i.test(ct[0] as string))
    return respond(415);
  if (req.body === undefined) return respond(400);
  let raw: string;
  try {
    raw = await req.body();
  } catch {
    return respond(400);
  }
  if (typeof raw !== 'string') return respond(400);
  if (raw.length > MAX_FORM_BYTES || encoder.encode(raw).length > MAX_FORM_BYTES)
    return respond(413);
  const form = new URLSearchParams(raw);
  const keys = [...form.keys()];
  if (keys.length !== 1 || keys[0] !== 'rg_clearance') return respond(400);
  const token = form.get('rg_clearance') as string;
  const s = await verifySession(
    token,
    b.tokenKeys,
    { siteId: b.siteId, host: req.host },
    bundleOf(b),
    nowSec,
  );
  if (s.kind !== 'valid' || s.lvl < 1) return respond(403);
  const cookie = setCookie(COOKIE_CLEARANCE, token, maxAge(token, nowSec, b.session.clearanceTtl));
  if (cookie === null) return respond(403);
  const want = req.cookies[COOKIE_RETURN];
  const to = typeof want === 'string' && isSafeReturnPath(want) ? want : '/';
  return respond(303, [
    ['Location', to],
    ['Set-Cookie', cookie],
    ['Set-Cookie', clearCookie(COOKIE_RETURN)],
  ]);
}
