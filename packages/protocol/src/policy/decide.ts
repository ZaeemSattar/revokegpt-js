import { compileGlob, type Glob, globMatch } from './glob.js';
import { scoreBucket } from './headers.js';
import { hostMatches, requestHost } from './host.js';
import { POLICY_LIMITS } from './limits.js';
import { normalizePath } from './normalize.js';
import {
  isSafeRedirectLocation,
  isTerminalAction,
  type PolicyBundlePayload,
  type PolicyRule,
} from './schema.js';

export interface PolicyRequest {
  /** The Host header (or URL authority); a port is stripped. */
  host: string;
  /** The method exactly as received; it must be upper case (`[A-Z][A-Z-]*`) or the request is refused. */
  method: string;
  /** The raw request target (origin-form), before any framework rewriting. */
  rawTarget: string;
  fetchMode: 'navigate' | 'other';
  acceptsHtml: boolean;
}

export type SessionState =
  | { kind: 'none' }
  | { kind: 'valid'; lvl: 0 | 1 | 2; sc: 0 | 1 | 2 | 3 }
  | { kind: 'invalid' };

export type VerifyOutcome =
  | { kind: 'absent' }
  | { kind: 'pass'; score: number }
  | { kind: 'fail'; reason: string }
  | { kind: 'unreachable' };

export interface Decision {
  kind: 'allow' | 'block' | 'challenge' | 'redirect' | 'needs-verify';
  /** Index of the terminal rule, or null (implicit allow, request refused before rules, fail mode). */
  ruleIndex: number | null;
  status?: number;
  location?: string;
  /** Headers to set toward the origin (`allow`) or on the response (`challenge`). */
  setHeaders: Record<string, string>;
  verify?: { expectedAction: string; threshold: number };
}

const READ_METHODS = ['GET', 'HEAD', 'OPTIONS'];
const METHOD_RE = /^[A-Z][A-Z-]{0,31}$/;
/** `sc` bucket to the lower bound of its score range in hundredths (0, 0.25, 0.5, 0.75). */
const SC_FLOOR_HUNDREDTHS = [0, 25, 50, 75];

/** The session score bucket `sc` (0-3) for a siteverify score: quarters of the range, 1.0 is bucket 3. */
export function sessionScoreBucket(score: number): 0 | 1 | 2 | 3 {
  if (typeof score !== 'number' || !Number.isFinite(score) || score <= 0) return 0;
  if (score >= 0.75) return 3;
  if (score >= 0.5) return 2;
  if (score >= 0.25) return 1;
  return 0;
}

const globCache = new WeakMap<PolicyRule, Glob | null>();
function globOf(r: PolicyRule): Glob | null {
  let g = globCache.get(r);
  if (g === undefined) {
    g = compileGlob(r.match.path);
    globCache.set(r, g);
  }
  return g;
}

function methodMatches(methods: readonly string[], method: string): boolean {
  if (methods.includes(method)) return true;
  if (method === 'OPTIONS') return false; // OPTIONS only matches a rule that lists it
  if (methods.includes('*')) return true;
  return method === 'HEAD' && methods.includes('GET');
}

function whenHolds(when: PolicyRule['when'], s: SessionState): boolean {
  if (when === undefined) return true;
  const valid = s.kind === 'valid';
  if (when.noSession === true && valid) return false;
  if (when.sessionLevelBelow !== undefined) {
    const lvl = s.kind === 'valid' ? s.lvl : -1;
    if (!(lvl < when.sessionLevelBelow)) return false;
  }
  if (when.scoreBelow !== undefined) {
    // No valid session: the score is unknown, which counts as below any threshold.
    if (
      s.kind === 'valid' &&
      !((SC_FLOOR_HUNDREDTHS[s.sc] as number) < Math.round(when.scoreBelow * 100))
    )
      return false;
  }
  return true;
}

const rank: Record<Decision['kind'], number> = {
  allow: 1,
  'needs-verify': 2,
  challenge: 3,
  redirect: 4,
  block: 5,
};

function stricter(a: Decision, b: Decision): Decision {
  if (rank[a.kind] !== rank[b.kind]) return rank[a.kind] > rank[b.kind] ? a : b;
  const ai = a.ruleIndex ?? Number.POSITIVE_INFINITY;
  const bi = b.ruleIndex ?? Number.POSITIVE_INFINITY;
  return bi < ai ? b : a;
}

const blockDecision = (
  status: number,
  ruleIndex: number | null,
  setHeaders: Record<string, string> = {},
): Decision => ({ kind: 'block', ruleIndex, status, setHeaders });

function scoreHeaders(v: VerifyOutcome | null, s: SessionState): Record<string, string> {
  if (v !== null && v.kind === 'pass')
    return { 'X-RG-Score': scoreBucket(v.score), 'X-RG-Verdict': 'pass' };
  if (s.kind === 'valid')
    return {
      'X-RG-Score': scoreBucket((SC_FLOOR_HUNDREDTHS[s.sc] as number) / 100),
      'X-RG-Verdict': 'pass',
    };
  return { 'X-RG-Score': '0', 'X-RG-Verdict': 'none' };
}

function evaluate(
  b: PolicyBundlePayload,
  host: string,
  method: string,
  path: string,
  r: PolicyRequest,
  s: SessionState,
  v: VerifyOutcome | null,
): Decision {
  const headers: Record<string, string> = {};
  let wantScore = false;
  // Headers accumulated by non-terminal actions of the rules matched so far (plus the score
  // headers when a `scoreHeader` matched). Every decision kind carries them; only an `allow`
  // applies them to the request sent to the origin.
  const acc = (): Record<string, string> => {
    const h: Record<string, string> = { ...headers };
    if (wantScore) Object.assign(h, scoreHeaders(v, s));
    return h;
  };
  const finishAllow = (ruleIndex: number | null, extra: Record<string, string> = {}): Decision => {
    const h = acc();
    Object.assign(h, extra);
    if (ruleIndex !== null) h['X-RG-Rule'] = String(ruleIndex);
    return { kind: 'allow', ruleIndex, setHeaders: h };
  };
  for (let i = 0; i < b.policies.length; i++) {
    const rule = b.policies[i] as PolicyRule;
    if (!rule.enabled) continue;
    if (!methodMatches(rule.match.methods, method)) continue;
    if (!rule.match.hosts.some((p) => hostMatches(p, host))) continue;
    const g = globOf(rule);
    if (g === null || !globMatch(g, path)) continue;
    if (!whenHolds(rule.when, s)) continue;
    let terminal: PolicyRule['actions'][number] | null = null;
    for (const a of rule.actions) {
      if (a.type === 'setHeader') headers[a.name] = a.value;
      else if (a.type === 'scoreHeader') wantScore = true;
      else if (isTerminalAction(a)) terminal = a;
    }
    if (terminal === null) continue;
    switch (terminal.type) {
      case 'allow':
        return finishAllow(i);
      case 'block':
        return blockDecision(terminal.status, i, acc());
      case 'redirect':
        // Re-checked here as well as in the editor: a bundle is data, never trusted blindly.
        if (!isSafeRedirectLocation(terminal.location, b.hosts))
          return blockDecision(403, i, acc());
        return {
          kind: 'redirect',
          ruleIndex: i,
          status: terminal.status,
          location: terminal.location,
          setHeaders: acc(),
        };
      case 'challengePage': {
        if (s.kind === 'valid' && s.lvl >= terminal.minLevel) return finishAllow(i);
        const nav = method === 'GET' && r.fetchMode === 'navigate' && r.acceptsHtml;
        if (nav)
          return {
            kind: 'challenge',
            ruleIndex: i,
            status: 303,
            location: `${b.challengeBase}/c/${b.siteKey}?h=${host}`,
            setHeaders: acc(),
          };
        return {
          kind: 'challenge',
          ruleIndex: i,
          status: 403,
          setHeaders: { ...acc(), 'X-RG-Action': 'challenge' },
        };
      }
      case 'requireToken': {
        if (v === null)
          return {
            kind: 'needs-verify',
            ruleIndex: i,
            setHeaders: acc(),
            verify: { expectedAction: terminal.action, threshold: terminal.threshold },
          };
        if (v.kind === 'unreachable')
          return rule.onError === 'allow'
            ? finishAllow(i, { 'X-RG-Verdict': 'none' })
            : blockDecision(403, i, acc());
        if (v.kind === 'pass') {
          if (Math.round(v.score * 1e6) >= Math.round(terminal.threshold * 1e6)) {
            wantScore = true;
            return finishAllow(i);
          }
          return blockDecision(403, i, acc());
        }
        return blockDecision(403, i, acc()); // absent or fail
      }
      default:
        continue;
    }
  }
  return finishAllow(null);
}

/**
 * The firewall decision for one request (protocol v1, section 18.4). Pure and total.
 *
 * Order: (1) a bundle past `expiresAt + 6 h` applies its fail mode (open: allow, closed: 503);
 * (2) a method that is not upper case, or a host that is not a canonical hostname, is a 400;
 * (3) a path that is not origin-form or holds a bad escape is a 400; a non-canonical path
 * follows `onNonCanonical` (`block`: 403 for every method; `block-writes`: 403 for methods other
 * than GET, HEAD and OPTIONS, and an allow marked `X-RG-Path: non-canonical` for those);
 * (4) rules run top to bottom on both forms of the path (`path` and `collapsed`, see
 * `normalizePath`); the stricter decision wins (block, redirect, challenge, needs-verify, allow).
 * `v` is null until the integration has called siteverify: a matching `requireToken` rule then
 * returns `needs-verify`, and the integration calls `decide` again with the outcome. A session in
 * state `none` or `invalid` never satisfies a `when`, and never skips a `requireToken`.
 */
export function decide(
  b: PolicyBundlePayload,
  r: PolicyRequest,
  s: SessionState,
  v: VerifyOutcome | null,
  now: number,
): Decision {
  if (now > b.expiresAt + POLICY_LIMITS.staleGraceSeconds)
    return b.failMode === 'open'
      ? { kind: 'allow', ruleIndex: null, setHeaders: { 'X-RG-Verdict': 'none' } }
      : blockDecision(503, null);
  // Kill switch (section 18.5): a verified, non-stale bundle with disabled=true passes every request through.
  if (b.disabled === true) return { kind: 'allow', ruleIndex: null, setHeaders: {} };
  if (typeof r.method !== 'string' || !METHOD_RE.test(r.method)) return blockDecision(400, null);
  const host = requestHost(r.host);
  if (host === null) return blockDecision(400, null);
  const n = normalizePath(r.rawTarget);
  if (!n.ok) {
    if (n.reason === 'invalid') return blockDecision(400, null);
    if (b.onNonCanonical === 'block' || !READ_METHODS.includes(r.method))
      return blockDecision(403, null);
    return {
      kind: 'allow',
      ruleIndex: null,
      setHeaders: { 'X-RG-Verdict': 'none', 'X-RG-Path': 'non-canonical' },
    };
  }
  const first = evaluate(b, host, r.method, n.path, r, s, v);
  if (n.collapsed === n.path) return first;
  return stricter(first, evaluate(b, host, r.method, n.collapsed, r, s, v));
}
