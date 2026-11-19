/**
 * `@revokegpt/node`: the RevokeGPT server SDK for Node.js.
 *
 * `createClient({ secret, endpoint })` returns a client whose `verify(token, options)` calls
 * siteverify (protocol v1 section 10) and applies the relying-party checks of section 7: the
 * response is read strictly (`parseSiteverifyResult`), then `checkSiteverifyResult` compares its
 * hostname (or, for a mobile app token, app id), action and score with what the caller expects. Gate on `outcome.ok` alone.
 */
import {
  canonicalizeIp,
  checkSiteverifyResult,
  isSiteKey,
  parseSecretKey,
  parseSiteverifyResult,
  RESPONSE_TOKEN_RE,
  type SiteverifyCheckReason,
  type SiteverifyExpectation,
  type SiteverifyResult,
} from '@revokegpt/protocol';
import { abortable, discard } from './abort.js';
import {
  type AnnotateInput,
  type Assessment,
  assessmentsBase,
  type CreateAssessmentInput,
  createAssessmentApi,
  type EraseAccountInput,
} from './assessments.js';

export type { SiteverifyCheckReason, SiteverifyResult } from '@revokegpt/protocol';
export type {
  AccountRef,
  AccountVerificationEndpoint,
  AccountVerificationInput,
  AnnotateInput,
  Assessment,
  CreateAssessmentInput,
  EraseAccountInput,
  RevokeGPTErrorCode,
  UserIdInput,
  UserInfoInput,
} from './assessments.js';
export { RevokeGPTError, RevokeGPTUnavailable } from './assessments.js';
export type { TransactionDataInput } from './payments.js';
export { cardFields } from './payments.js';

/** The mobile app a token must have been issued to (protocol v1 section 7). */
export type ExpectedApp = {
  platform: 'android' | 'ios';
  /** Android: the package name (`apk_package_name`). iOS: the bare bundle id, without the Team ID. */
  id: string;
};

/** What the token must have been issued for: exactly one of a web hostname or a mobile app. */
type Target =
  | {
      /** The hostname the token must carry, canonical (lowercase, no trailing dot), compared exactly. */
      expectedHostname: string;
      expectedApp?: never;
    }
  | {
      /** The app the token must carry, compared exactly. Not combinable with `expectedHostname`. */
      expectedApp: ExpectedApp;
      expectedHostname?: never;
    };

export type VerifyOptions = Target & {
  /** The action this endpoint serves. Omitted: only a token without an action passes. */
  expectedAction?: string;
  /** Score threshold in [0, 1]. Required whenever the result carries a score. */
  minScore?: number;
  /** End-user IP address (IPv4 or IPv6). Sent only when given and not the empty string. */
  remoteip?: string;
  /** The site key the token must belong to. Sent only when given and not the empty string. */
  sitekey?: string;
};

export type VerifyFailureReason =
  | SiteverifyCheckReason
  | 'invalid-options'
  | 'invalid-token-format'
  | 'network-error'
  | 'http-error';

/**
 * `ok` is true only when siteverify verified the token and every relying-party check passed; then
 * there is no `reason`. `result` is the parsed siteverify result, or the "not verified" result when
 * no 200 body was read.
 */
export type VerifyOutcome =
  | { ok: true; result: SiteverifyResult }
  | { ok: false; reason: VerifyFailureReason; result: SiteverifyResult };

export type ClientOptions = {
  /** The site's secret key (`rgsk_...`). Held privately by the client and sent only in the body. */
  secret: string;
  /** The full siteverify URL, such as `https://<api host>/v1/siteverify`. */
  endpoint: string;
  /** Request timeout in milliseconds, an integer in [1, 60000]. Default 5000. */
  timeoutMs?: number;
  /**
   * A WHATWG-compatible `fetch` (its response `body` a web `ReadableStream`). Default: the global
   * `fetch` at the time the client is created.
   */
  fetch?: typeof fetch;
};

export type Client = {
  /** Verifies `token`. Never throws and never rejects: every failure is an outcome. */
  verify(token: string, options: VerifyOptions): Promise<VerifyOutcome>;
  /** `POST /v1/assessments` (derived from the siteverify endpoint). Throws `RevokeGPTError` on a failure. */
  createAssessment(input: CreateAssessmentInput): Promise<Assessment>;
  /** Labels an assessment; accepts `assessments/<aid>` or the bare aid. Throws `RevokeGPTError`. */
  annotate(aidOrName: string, input?: AnnotateInput): Promise<void>;
  /** Erases everything stored for an account (`POST /v1/accounts:erase`). Throws `RevokeGPTError`. */
  eraseAccount(input: EraseAccountInput): Promise<void>;
};

const DEFAULT_TIMEOUT_MS = 5000;
const MAX_TIMEOUT_MS = 60_000;
/** The most response bytes read; a longer body is `http-error` (a hostile endpoint cannot exhaust memory). */
const MAX_RESPONSE_BYTES = 64 * 1024;
const LOCAL_HTTP_HOSTS = new Set(['localhost', '127.0.0.1']);

// A private copy of the token pattern, so later changes to the exported object cannot affect it.
const TOKEN_RE = new RegExp(RESPONSE_TOKEN_RE.source, RESPONSE_TOKEN_RE.flags);

/** `obj[key]` if `key` is an own property of `obj`, else undefined (never an inherited value). */
function own(obj: object, key: string): unknown {
  return Object.hasOwn(obj, key) ? (obj as Record<string, unknown>)[key] : undefined;
}

/** A fresh "not verified" result (every field own: `false`, `null` or `[]`). */
const notVerified = (): SiteverifyResult => parseSiteverifyResult('');

const failure = (reason: VerifyFailureReason, result = notVerified()): VerifyOutcome => ({
  ok: false,
  reason,
  result,
});

/** Validates the endpoint. Messages never include the value (it may carry credentials). */
function parseEndpoint(endpoint: unknown): string {
  if (typeof endpoint !== 'string') throw new TypeError('invalid endpoint: must be a string');
  // `?` and `#` are refused anywhere, even empty (`new URL` drops an empty query or fragment).
  if (endpoint.includes('?') || endpoint.includes('#'))
    throw new TypeError('invalid endpoint: no query or fragment allowed');
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new TypeError('invalid endpoint: must be an absolute URL');
  }
  if (url.username !== '' || url.password !== '')
    throw new TypeError('invalid endpoint: no username or password allowed');
  const secure = url.protocol === 'https:';
  const local = url.protocol === 'http:' && LOCAL_HTTP_HOSTS.has(url.hostname);
  if (!secure && !local)
    throw new TypeError('invalid endpoint: must be https (http only for localhost or 127.0.0.1)');
  return url.href;
}

function parseTimeout(timeoutMs: unknown): number {
  if (timeoutMs === undefined) return DEFAULT_TIMEOUT_MS;
  if (typeof timeoutMs !== 'number' || !Number.isInteger(timeoutMs))
    throw new TypeError('invalid timeoutMs: must be an integer');
  if (timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS)
    throw new RangeError(`invalid timeoutMs: must be between 1 and ${MAX_TIMEOUT_MS}`);
  return timeoutMs;
}

type ReadOptions =
  | { reason: 'invalid-expectation' }
  | { reason: 'invalid-options' }
  | { reason?: undefined; expect: SiteverifyExpectation; extra: [string, string][] };

/**
 * The verify options as a checked expectation and optional body fields. Only own properties are
 * read, so a polluted `Object.prototype.minScore` (say 0) cannot loosen the check, nor a polluted
 * `remoteip` reach the body. Never throws:
 * - `invalid-expectation`: `o` is not an object, or not exactly one of expectedHostname and
 *   expectedApp is given, or expectedHostname, expectedApp, expectedAction or minScore is invalid (as `checkSiteverifyResult` judges it) or has a throwing getter;
 * - `invalid-options`: a non-empty remoteip or sitekey is invalid or has a throwing getter.
 */
function readOptions(o: unknown): ReadOptions {
  let expect: SiteverifyExpectation;
  try {
    if (typeof o !== 'object' || o === null) return { reason: 'invalid-expectation' };
    const e: Record<string, unknown> = {};
    // Exactly one of hostname and app is judged by checkSiteverifyResult (`undefined` is absent).
    const hostname = own(o, 'expectedHostname');
    const app = own(o, 'expectedApp');
    if (hostname !== undefined) e.hostname = hostname;
    if (app !== undefined)
      // Rebuilt from own properties, so an inherited platform or id cannot reach the check.
      e.app =
        typeof app === 'object' && app !== null
          ? { platform: own(app, 'platform'), id: own(app, 'id') }
          : app;
    const action = own(o, 'expectedAction');
    const minScore = own(o, 'minScore');
    if (action !== undefined) e.action = action;
    if (minScore !== undefined) e.minScore = minScore;
    expect = e as SiteverifyExpectation;
    // The reference check validates the expectation first: on a "not verified" result it answers
    // invalid-expectation for a bad one and not-verified for a good one.
    if (checkSiteverifyResult(notVerified(), expect).reason === 'invalid-expectation')
      return { reason: 'invalid-expectation' };
  } catch {
    return { reason: 'invalid-expectation' };
  }

  try {
    const extra: [string, string][] = [];
    // Undefined or empty: not sent (siteverify refuses an empty remoteip as bad-request).
    const remoteip = own(o, 'remoteip');
    if (remoteip !== undefined && remoteip !== '') {
      if (typeof remoteip !== 'string' || canonicalizeIp(remoteip) === null)
        return { reason: 'invalid-options' };
      extra.push(['remoteip', remoteip]);
    }
    const sitekey = own(o, 'sitekey');
    if (sitekey !== undefined && sitekey !== '') {
      if (typeof sitekey !== 'string' || !isSiteKey(sitekey)) return { reason: 'invalid-options' };
      extra.push(['sitekey', sitekey]);
    }
    return { expect, extra };
  } catch {
    return { reason: 'invalid-options' };
  }
}

/** Thrown inside `readCapped` when the body is over the cap. */
class TooLarge extends Error {}

/**
 * Reads at most `MAX_RESPONSE_BYTES` of `body`. Throws `TooLarge` beyond the cap (after cancelling
 * the stream), and the stream's or the signal's error otherwise.
 */
async function readCapped(body: unknown, signal: AbortSignal): Promise<Uint8Array> {
  if (body === null || body === undefined) return new Uint8Array(0);
  const reader = (body as ReadableStream<Uint8Array>).getReader();
  const out = new Uint8Array(MAX_RESPONSE_BYTES);
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await abortable(reader.read(), signal);
      if (done) return out.slice(0, length);
      if (!(value instanceof Uint8Array)) throw new TypeError('response chunk is not bytes');
      if (length + value.byteLength > MAX_RESPONSE_BYTES) throw new TooLarge();
      out.set(value, length);
      length += value.byteLength;
    }
  } catch (e) {
    discard(reader);
    throw e;
  }
}

/**
 * Creates a siteverify client. Throws `TypeError` (or `RangeError` for an out-of-range timeout)
 * when an option is invalid; no message ever includes the secret or the endpoint. The secret is
 * held in a closure: it is not a property of the client, so logging or serializing the client
 * never shows it.
 */
export function createClient(opts: ClientOptions): Client {
  if (typeof opts !== 'object' || opts === null) throw new TypeError('invalid options');
  const secret = own(opts, 'secret');
  const parsed = typeof secret === 'string' ? parseSecretKey(secret) : null;
  // A management key (`rgmk_`) is not a siteverify secret.
  if (parsed === null || parsed.kind !== 'secret') throw new TypeError('invalid secret key');
  const secretKey = secret as string;
  const endpoint = parseEndpoint(own(opts, 'endpoint'));
  const timeoutMs = parseTimeout(own(opts, 'timeoutMs'));
  const given = own(opts, 'fetch');
  if (given !== undefined && typeof given !== 'function')
    throw new TypeError('invalid fetch: must be a function');
  const fetchImpl = (given ?? globalThis.fetch) as typeof fetch;
  if (typeof fetchImpl !== 'function') throw new TypeError('no fetch implementation available');

  const assessments = createAssessmentApi({
    secret: secretKey,
    base: assessmentsBase(endpoint),
    endpoint,
    timeoutMs,
    fetchImpl,
  });

  async function verify(token: string, options: VerifyOptions): Promise<VerifyOutcome> {
    try {
      // Precedence: invalid-expectation, then invalid-options, then invalid-token-format.
      const checked = readOptions(options);
      if (checked.reason !== undefined) return failure(checked.reason);
      if (typeof token !== 'string' || !TOKEN_RE.test(token))
        return failure('invalid-token-format');

      // Form-encoded by URLSearchParams, never concatenated: a value cannot inject a field.
      const body = new URLSearchParams([
        ['secret', secretKey],
        ['response', token],
        ...checked.extra,
      ]).toString();
      const signal = AbortSignal.timeout(timeoutMs);

      let text: string;
      try {
        const res: unknown = await abortable(
          Promise.resolve(
            fetchImpl(endpoint, {
              method: 'POST',
              headers: {
                'content-type': 'application/x-www-form-urlencoded',
                accept: 'application/json',
                // No compression: a small bomb inflates to a large RSS spike before the 64 KiB
                // cap trips (M1R1 S-5). The server never compresses a siteverify answer.
                'accept-encoding': 'identity',
              },
              body,
              // Never follow a redirect: a 307 or 308 would re-send the secret elsewhere.
              redirect: 'manual',
              signal,
            }),
          ),
          signal,
          // The abort won against a fetch that ignored the signal: release the late body.
          (late) => discard((late as { body?: unknown } | null | undefined)?.body),
        );
        if (typeof res !== 'object' || res === null) return failure('network-error');
        const responseBody = (res as { body?: unknown }).body;
        // Any status other than 200 (redirects included) is "not verified" (section 7).
        if ((res as { status?: unknown }).status !== 200) {
          discard(responseBody);
          return failure('http-error');
        }
        // A body in any content coding is refused unread: the request asked for identity.
        const coding = (res as { headers?: { get?: (n: string) => unknown } }).headers?.get?.(
          'content-encoding',
        );
        if (typeof coding === 'string' && coding.trim() !== '' && coding.trim() !== 'identity') {
          discard(responseBody);
          return failure('http-error');
        }
        const bytes = await readCapped(responseBody, signal);
        try {
          // Strict: invalid UTF-8 throws, and a leading BOM is kept so JSON.parse refuses it (as
          // Python's json.loads and Go's encoding/json do), never stripped.
          text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
        } catch {
          text = ''; // Not UTF-8: unparseable, so "not verified".
        }
      } catch (e) {
        return failure(e instanceof TooLarge ? 'http-error' : 'network-error');
      }

      const result = parseSiteverifyResult(text);
      const check = checkSiteverifyResult(result, checked.expect);
      return check.ok ? { ok: true, result } : failure(check.reason ?? 'not-verified', result);
    } catch {
      return failure('not-verified');
    }
  }

  return Object.freeze({
    verify,
    createAssessment: assessments.createAssessment,
    annotate: assessments.annotate,
    eraseAccount: assessments.eraseAccount,
  });
}
