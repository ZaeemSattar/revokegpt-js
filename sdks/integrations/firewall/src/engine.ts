import {
  type Decision,
  decide,
  normalizePath,
  POLICY_LIMITS,
  type PolicyBundlePayload,
  type PolicyRequest,
  requestHost,
  type SessionState,
  stripRgHeaders,
  type VerifyOutcome,
  verifySession,
} from '@revokegpt/protocol';
import { Breaker } from './breaker.js';
import { BundleCache } from './bundle-cache.js';
import { type FirewallConfig, resolveConfig } from './config.js';
import {
  COOKIE_CLEARANCE,
  COOKIE_RETURN,
  COOKIE_SESSION,
  isCookieSafe,
  setCookie,
} from './cookies.js';
import {
  type FwRequest,
  type FwResult,
  handleReturn,
  handleSession,
  header,
  isSafeReturnPath,
  respond,
} from './rg-routes.js';
import { createVerifier, isWellFormedToken } from './verify-client.js';

export interface Firewall {
  /** Decides one request. Never rejects: an internal error is a closed 503. */
  handle(req: FwRequest): Promise<FwResult>;
  /** Fetches the policy bundle now (warm-up). Never rejects. */
  refresh(): Promise<void>;
}

const MAX_RETURN_PATH = 2048;
const RETURN_COOKIE_SECONDS = 600;
const SESSION_RANK = (s: SessionState): number => (s.kind === 'valid' ? s.lvl + 1 : 0);

function randomId(): string {
  const b = new Uint8Array(8);
  globalThis.crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

async function hmacHex(secret: string, data: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key, enc.encode(data)));
  return Array.from(mac, (x) => x.toString(16).padStart(2, '0')).join('');
}

export function createFirewall(config: FirewallConfig): Firewall {
  const c = resolveConfig(config);
  /** A configuration problem, in the decision-log shape only (never a secret or a URL). */
  const logConfig = (action: string): void => {
    try {
      c.log({ decisionId: randomId(), ruleIndex: null, action });
    } catch {
      // a logger never changes a decision
    }
  };
  let sigWarned = false;
  const nowSec = (): number => Math.floor(c.now() / 1000);
  const cache = new BundleCache({
    url: `${c.apiBase}/v1/policies/${c.siteKey}`,
    siteKey: c.siteKey,
    pinned: c.pinnedKeys,
    fetch: c.fetch,
    now: c.now,
    store: c.store,
    refreshMs: c.bundleRefreshMs,
    strictSiteKey: c.strictSiteKey,
    ...(c.secretKey === null ? {} : { secretKey: c.secretKey }),
    onAuthError: () => logConfig('config-error:bundle-unauthorized'),
    ...(c.verifiedCache === undefined ? {} : { verifiedCache: c.verifiedCache }),
  });
  const breaker = new Breaker(5, 30_000, c.now);
  const verifier =
    c.secretKey === null
      ? null
      : createVerifier({
          apiBase: c.apiBase,
          secretKey: c.secretKey,
          integration: c.integration,
          fetch: c.fetch,
        });

  async function sessionState(
    req: FwRequest,
    b: PolicyBundlePayload,
    now: number,
  ): Promise<SessionState> {
    const expect = { siteId: b.siteId, host: req.host };
    const tokens = [req.cookies[COOKIE_CLEARANCE], req.cookies[COOKIE_SESSION]];
    let best: SessionState = { kind: 'none' };
    for (const t of tokens) {
      const s = await verifySession(t, b.tokenKeys, expect, b, now);
      // A valid token wins over an invalid one; an invalid one over none.
      if (SESSION_RANK(s) > SESSION_RANK(best) || (best.kind === 'none' && s.kind === 'invalid'))
        best = s;
    }
    return best;
  }

  async function outcome(req: FwRequest, host: string, expected: string): Promise<VerifyOutcome> {
    const given = header(req, 'x-rg-token');
    if (given.length === 0) return { kind: 'absent' };
    const token = given[0] as string;
    if (given.length > 1 || !isWellFormedToken(token))
      return { kind: 'fail', reason: 'malformed-token' };
    if (verifier === null || !breaker.allow()) return { kind: 'unreachable' };
    const v = await verifier.verify(token, { hostname: host, action: expected });
    if (v.kind === 'unreachable') breaker.failure();
    else breaker.success();
    return v;
  }

  function returnCookie(req: FwRequest): [string, string][] {
    const n = normalizePath(req.rawTarget);
    if (!n.ok) return [];
    const q = req.rawTarget.indexOf('?');
    const h = req.rawTarget.indexOf('#');
    const query = q < 0 ? '' : req.rawTarget.slice(q, h > q ? h : undefined);
    const path = n.path + query;
    if (path.length > MAX_RETURN_PATH || !isSafeReturnPath(path) || !isCookieSafe(path)) return [];
    const cookie = setCookie(COOKIE_RETURN, path, RETURN_COOKIE_SECONDS);
    return cookie === null ? [] : [['Set-Cookie', cookie]];
  }

  async function sign(
    req: FwRequest,
    host: string,
    h: Record<string, string>,
    bundleWantsSig: boolean,
  ): Promise<Record<string, string>> {
    // Signed only when the bundle's settings turn it on AND a sigSecret is configured here.
    if (!bundleWantsSig) return h;
    if (c.sigSecret === null) {
      if (!sigWarned) {
        sigWarned = true;
        logConfig('config-warning:sig-secret-missing');
      }
      return h;
    }
    const t = nowSec();
    const n = normalizePath(req.rawTarget);
    const data = [
      t,
      host,
      req.method,
      n.ok ? n.path : '',
      h['X-RG-Score'] ?? '',
      h['X-RG-Verdict'] ?? '',
      h['X-RG-Rule'] ?? '',
    ].join('\n');
    return { ...h, 'X-RG-Sig': `t=${t},v1=${await hmacHex(c.sigSecret, data)}` };
  }

  function toResult(d: Decision, req: FwRequest): FwResult {
    switch (d.kind) {
      case 'block':
        return respond(d.status ?? 403);
      case 'redirect':
        return respond(d.status ?? 302, [['Location', d.location ?? '/']]);
      case 'challenge': {
        const extra: [string, string][] = Object.entries(d.setHeaders);
        if (d.status === 303 && d.location !== undefined)
          return respond(303, [['Location', d.location], ...returnCookie(req), ...extra]);
        return respond(d.status ?? 403, extra);
      }
      default:
        return respond(503);
    }
  }

  async function inner(req: FwRequest): Promise<FwResult> {
    const stripHeaders = stripRgHeaders(req.headers.map(([n]) => n));
    const now = nowSec();
    const cut = req.rawTarget.search(/[?#]/);
    const pathOnly = cut < 0 ? req.rawTarget : req.rawTarget.slice(0, cut);
    const reserved = reservedKind(pathOnly, req.rawTarget);
    const b = await cache.get(req.waitUntil);
    if (b === null) {
      if (reserved !== null) return respond(503);
      if (!cache.noPolicies && c.initialFailMode === 'closed') return respond(503);
      return { type: 'pass', stripHeaders, setHeaders: { 'X-RG-Verdict': 'none' } };
    }
    // Kill switch: a verified bundle that says `disabled` lets everything through untouched, whatever
    // the fail mode. Spoofed inbound X-RG-* headers are still stripped; nothing is set, signed or verified.
    // (red team E-2: a stale bundle is not trusted, so its kill switch is not either (v1.md 18.5)): past expiresAt + 6 h the fail mode applies through `decide`.
    if (b.disabled === true && now <= b.expiresAt + POLICY_LIMITS.staleGraceSeconds)
      return { type: 'pass', stripHeaders, setHeaders: {} };
    if (reserved === 'session') return handleSession(req, b, now);
    if (reserved === 'return') return handleReturn(req, b, now);
    if (reserved === 'other') return respond(404);

    const host = requestHost(req.host);
    const fetchMode =
      header(req, 'sec-fetch-mode')[0]?.toLowerCase() === 'navigate' ? 'navigate' : 'other';
    const pr: PolicyRequest = {
      host: req.host,
      method: req.method,
      rawTarget: req.rawTarget,
      fetchMode,
      acceptsHtml: header(req, 'accept').some((a) => /text\/html/i.test(a)),
    };
    const session = await sessionState(req, b, now);
    let d = decide(b, pr, session, null, now);
    if (d.kind === 'needs-verify' && d.verify !== undefined && host !== null) {
      const v = await outcome(req, host, d.verify.expectedAction);
      d = decide(b, pr, session, v, now);
    }
    try {
      c.log({
        decisionId: randomId(),
        ruleIndex: d.ruleIndex,
        action: d.kind === 'needs-verify' ? 'block' : d.kind,
      });
    } catch {
      // a logger never changes a decision
    }
    if (d.kind === 'allow')
      return {
        type: 'pass',
        stripHeaders,
        setHeaders: await sign(req, host ?? '', d.setHeaders, b.sigHeader === true),
      };
    return toResult(d, req);
  }

  return {
    async handle(req) {
      try {
        return await inner(req);
      } catch {
        return respond(503);
      }
    },
    refresh: () => cache.refresh(),
  };
}

/** Which reserved route a request target is: the two handled paths exactly, anything else in the `/__rg` namespace. */
function reservedKind(pathOnly: string, rawTarget: string): 'session' | 'return' | 'other' | null {
  if (pathOnly === '/__rg/session') return 'session';
  if (pathOnly === '/__rg/return') return 'return';
  const n = normalizePath(rawTarget);
  const forms = n.ok ? [n.path, n.collapsed, pathOnly] : [pathOnly];
  for (const f of forms) {
    const l = f.toLowerCase().replace(/%5f/g, '_').replace(/%2f/g, '/');
    if (l === '/__rg' || l.startsWith('/__rg/')) return 'other';
  }
  return null;
}
