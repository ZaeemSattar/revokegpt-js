import {
  checkSiteverifyResult,
  parseSiteverifyResult,
  type VerifyOutcome,
} from '@revokegpt/protocol';

export interface VerifierOptions {
  apiBase: string;
  /** The secret now, or undefined while it is not available (then siteverify is `unreachable`). */
  secretKey: () => string | undefined;
  integration: string;
  fetch: typeof fetch;
  timeoutMs?: number;
}

/** Action tokens: 20 to 4096 characters of base64url and `.`, checked before any call. */
const TOKEN_SHAPE = /^[A-Za-z0-9_.-]{20,4096}$/;
const MAX_RESPONSE = 64 * 1024;

export const isWellFormedToken = (t: string): boolean => TOKEN_SHAPE.test(t);

/** Error codes that prove the request never reached the server (nothing was sent, so a retry cannot spend the token twice). */
const PRE_SEND_CODES = new Set([
  'ECONNREFUSED',
  'ENOTFOUND',
  'EAI_AGAIN',
  'ENETUNREACH',
  'EHOSTUNREACH',
]);

/**
 * True only when the failure is identifiably a connection-establishment error. `fetch` rejects with
 * the same TypeError for a refused connection and for a socket reset after the body was written, so
 * a runtime that does not expose the cause code (Workers, Compute) is never retried.
 */
export function isConnectError(e: unknown): boolean {
  let cur: unknown = e;
  for (let i = 0; i < 3 && typeof cur === 'object' && cur !== null; i++) {
    const code = (cur as { code?: unknown }).code;
    if (typeof code === 'string' && PRE_SEND_CODES.has(code)) return true;
    cur = (cur as { cause?: unknown }).cause;
  }
  return false;
}

/**
 * siteverify for the firewall: `POST /v1/siteverify` with `Authorization: Bearer rgsk_...` (the
 * secret travels nowhere else), the token in a form body, `X-RG-Integration`. ONE 2 s budget covers
 * every attempt, the send and the body read; at most one retry, and only when the first attempt
 * failed while establishing the connection (nothing was sent). Never retried on a timeout, a reset
 * after send, or any HTTP status. The result is checked against the request hostname and the
 * action the rule expects (protocol v1 section 7); the score is compared by `decide`.
 * Outcomes: `pass` with the score, `fail` (the service answered and said no, or the answer does
 * not match, or a 429 `rate-limited`), `unreachable` (no usable 200 answer: the breaker counts it).
 */
export function createVerifier(o: VerifierOptions) {
  const url = `${o.apiBase}/v1/siteverify`;
  const timeoutMs = o.timeoutMs ?? 2000;

  function attempt(
    token: string,
    secret: string,
    signal: AbortSignal | undefined,
  ): Promise<Response> {
    return o.fetch(url, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${secret}`,
        'x-rg-integration': o.integration,
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
      },
      body: new URLSearchParams([['response', token]]).toString(),
      // Never follow a redirect: it would re-send the Bearer secret elsewhere.
      redirect: 'manual',
      ...(signal === undefined ? {} : { signal }),
    });
  }

  async function run(
    token: string,
    secret: string,
    expect: { hostname: string; action: string },
    signal: AbortSignal | undefined,
    budget: { expired: boolean },
  ): Promise<VerifyOutcome> {
    let res: Response;
    try {
      try {
        res = await attempt(token, secret, signal);
      } catch (e) {
        if (budget.expired || signal?.aborted === true || !isConnectError(e))
          return { kind: 'unreachable' };
        res = await attempt(token, secret, signal); // the one retry, same budget
      }
    } catch {
      return { kind: 'unreachable' };
    }
    try {
      // A 429 is the edge answering, not an outage: the site is over its siteverify rate limit,
      // which a flood of junk tokens can cause. It fails this request closed and is never counted
      // by the breaker, so it cannot open the breaker into an `onError: allow` bypass (E-1).
      if (res.status === 429) {
        void res.body?.cancel().catch(() => {});
        return { kind: 'fail', reason: 'rate-limited' };
      }
      if (res.status !== 200) {
        void res.body?.cancel().catch(() => {});
        return { kind: 'unreachable' };
      }
      const text = await readCapped(res);
      if (text === null) return { kind: 'unreachable' };
      const result = parseSiteverifyResult(text);
      const check = checkSiteverifyResult(result, { ...expect, minScore: 0 });
      if (!check.ok) return { kind: 'fail', reason: check.reason ?? 'not-verified' };
      return { kind: 'pass', score: result.score as number };
    } catch {
      return { kind: 'unreachable' };
    }
  }

  return {
    async verify(
      token: string,
      expect: { hostname: string; action: string },
    ): Promise<VerifyOutcome> {
      const secret = o.secretKey();
      if (secret === undefined) return { kind: 'unreachable' };
      // Some runtimes (Fastly Compute) have no AbortController: the deadline race below still bounds the call.
      const ctl = typeof AbortController === 'function' ? new AbortController() : undefined;
      const budget = { expired: false };
      let timer: ReturnType<typeof setTimeout> | undefined;
      const expired = new Promise<VerifyOutcome>((ok) => {
        timer = setTimeout(() => {
          budget.expired = true;
          ctl?.abort();
          ok({ kind: 'unreachable' });
        }, timeoutMs);
      });
      try {
        return await Promise.race([run(token, secret, expect, ctl?.signal, budget), expired]);
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

async function readCapped(res: Response): Promise<string | null> {
  if (res.body === null) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.length;
    if (n > MAX_RESPONSE) {
      void reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(n);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.length;
  }
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(all);
}
