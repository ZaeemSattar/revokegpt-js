import {
  AccountVerificationRequest,
  type ANNOTATE_INPUT_REASONS,
  AnnotateRequest,
  type API_ERROR_CODES,
  type ASSESSMENT_ERROR_CODES,
  AssessmentResponse as AssessmentSchema,
  EraseRequest,
  type TransactionEvent,
  UserInfo,
} from '@revokegpt/protocol';
import { abortable, discard } from './abort.js';
import { checkTransactionData, scanForPan, type TransactionDataInput } from './payments.js';

export type { AssessmentResponse as Assessment } from '@revokegpt/protocol';

/** Codes the SDK itself adds to the server's (protocol section 7 and 14). */
export type RevokeGPTErrorCode =
  | (typeof ASSESSMENT_ERROR_CODES)[number]
  | (typeof API_ERROR_CODES)[number]
  | 'network-error'
  | 'invalid-response'
  | (string & {});

/** Thrown by `createAssessment` and `annotate` on a failed request. Never carries the secret. */
export class RevokeGPTError extends Error {
  readonly code: RevokeGPTErrorCode;
  /** HTTP status; 0 when no response was read (timeout, network failure). */
  readonly status: number;
  readonly requestId: string | undefined;
  /** Seconds from `Retry-After` (a 429), when sent. */
  readonly retryAfterSeconds: number | undefined;
  constructor(
    code: RevokeGPTErrorCode,
    status: number,
    extra: { requestId?: string; retryAfterSeconds?: number } = {},
  ) {
    super(`RevokeGPT request failed: ${code}`);
    this.name = 'RevokeGPTError';
    this.code = code;
    this.status = status;
    this.requestId = extra.requestId;
    this.retryAfterSeconds = extra.retryAfterSeconds;
  }
}

/**
 * Thrown when the service answers HTTP 503: the feature is switched off, or a data source cannot
 * be read. Treat it as "could not check":
 * retry later or fail closed.
 */
export class RevokeGPTUnavailable extends RevokeGPTError {
  constructor(extra: { requestId?: string; retryAfterSeconds?: number } = {}) {
    super('service-unavailable', 503, extra);
    this.name = 'RevokeGPTUnavailable';
  }
}

/**
 * The account an assessment, annotation or erase is about: exactly one of `accountId` and
 * `hashedAccountId`. The service keys it into an irreversible per-site hash; the raw value is
 * never stored or logged, but it does travel to the service over TLS. Use one form for an
 * account everywhere (assess, annotate, erase): the same account sent in the two forms gives two
 * different hashes.
 */
export type AccountRef =
  | {
      /** Your account identifier: 1 to 256 UTF-8 bytes. */
      accountId: string;
      hashedAccountId?: never;
    }
  | {
      accountId?: never;
      /** A hash of your account identifier that you computed: canonical padded base64 of exactly 32 bytes. */
      hashedAccountId: string;
    };

/** `event.userInfo`: the account of a token assessment (token assessments only, not `express`). */
export type UserInfoInput = (
  | AccountRef
  // No account: only the contact details below (a phone number is scored for SMS toll fraud).
  | { accountId?: never; hashedAccountId?: never; userIds: UserIdInput[] }
) & {
  /** When the account was created. At most 600 s before now makes this assessment an account creation. */
  createAccountTime?: string | Date;
  /**
   * Up to 10 contact details of the user, each with exactly one of `email`, `phoneNumber` and
   * `username`. With the site's `smsTollFraud` flag on, the first `phoneNumber` is scored (E.164;
   * a malformed one is a verdict, not an error); nothing else here is stored or logged.
   */
  userIds?: UserIdInput[];
};

/** One contact detail of `userInfo.userIds`: exactly one of the three. */
export type UserIdInput =
  | { email: string; phoneNumber?: never; username?: never }
  | { email?: never; phoneNumber: string; username?: never }
  | { email?: never; phoneNumber?: never; username: string };

/** An address a verification code is sent to. */
export type AccountVerificationEndpoint =
  | { emailAddress: string }
  | {
      /**
       * E.164. The schema accepts it, but SMS is not supported yet: the service answers 403
       * `feature-disabled` and sends nothing.
       */
      phoneNumber: string;
    };

/**
 * Asks for an email verification of the account in `userInfo` (protocol v1 section 17). Needs a
 * named account in `userInfo` and the site's `mfa` policy.
 */
export type AccountVerificationInput = {
  /** One or two endpoints; the response lists one `requestToken` per endpoint, in this order. */
  endpoints: AccountVerificationEndpoint[];
  /** BCP 47 code for the message; an unsupported language gets English. */
  languageCode?: string;
};

export type CreateAssessmentInput = {
  /** The response token to assess. Omit for an express assessment. */
  token?: string;
  expectedAction?: string;
  /** Express: score from the IP reputation alone, no token. */
  express?: boolean;
  /** End-user IP (express only). Behind a proxy pass the real client IP, not the proxy's. */
  userIpAddress?: string;
  userAgent?: string;
  headers?: string[];
  /**
   * The account, for account protection and verification (protocol v1 sections 15 and 17). The
   * service hashes it per site; the SDK does no hashing of its own.
   */
  userInfo?: UserInfoInput;
  /** Email verification (MFA) of the account in `userInfo`. */
  accountVerification?: AccountVerificationInput;
  /**
   * The payment to score, before you charge (protocol v1 section 20; token assessments only).
   * Only the BIN and last four of a card are accepted: build them with `cardFields`. A string that
   * holds a card number throws `RevokeGPTError('bad-request', 0)` before any request is made.
   */
  transactionData?: TransactionDataInput;
  /** `ENABLED` asks for the payment and phone verdicts; `DISABLED` skips them. */
  fraudPrevention?: 'FRAUD_PREVENTION_UNSPECIFIED' | 'ENABLED' | 'DISABLED';
};

export type AnnotateInput = {
  annotation?: 'LEGITIMATE' | 'FRAUDULENT';
  /** `PAYMENT_FRAUD` is accepted as an alias of `CHARGEBACK_FRAUD`. */
  reasons?: (typeof ANNOTATE_INPUT_REASONS)[number][];
  /** The outcome of a payment this assessment scored (`reason` is the gateway's own code). */
  transactionEvent?: TransactionEvent;
} & (
  | AccountRef // The account a password or two-factor outcome belongs to.
  | { accountId?: never; hashedAccountId?: never }
);

/** Exactly one of `accountId` and `hashedAccountId`. */
export type EraseAccountInput = AccountRef;

export type AssessmentApi = {
  createAssessment(input: CreateAssessmentInput): Promise<AssessmentResponse>;
  annotate(aidOrName: string, input?: AnnotateInput): Promise<void>;
  eraseAccount(input: EraseAccountInput): Promise<void>;
};

type AssessmentResponse = import('@revokegpt/protocol').AssessmentResponse;

/**
 * A plain copy of `o`'s own enumerable properties with their `undefined` values dropped. Unknown
 * keys are kept on purpose, so the strict protocol schema refuses them instead of the SDK silently
 * dropping a field (a misspelled one would otherwise be sent as if never given). Built with
 * `Object.fromEntries`, so a key such as `__proto__` becomes an ordinary property.
 */
function ownCopy(o: object): Record<string, unknown> {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined));
}

function hasAccount(u: unknown): boolean {
  const o = u as { accountId?: unknown; hashedAccountId?: unknown };
  return o.accountId !== undefined || o.hashedAccountId !== undefined;
}

const AID_RE = /^[A-Za-z0-9_-]{42}$/;
const MAX_BYTES = 64 * 1024;

/** The assessments base (`.../v1`) from a siteverify URL, or null when it does not end in `/siteverify`. */
export function assessmentsBase(endpoint: string): string | null {
  const url = new URL(endpoint);
  if (!url.pathname.endsWith('/siteverify')) return null;
  url.pathname = `${url.pathname.slice(0, -'/siteverify'.length)}/assessments`;
  return url.href;
}

/** The v1 root (`.../v1`) from a siteverify URL, or null when it does not end in `/siteverify`. */
function v1Root(endpoint: string): string | null {
  const base = assessmentsBase(endpoint);
  return base === null ? null : base.slice(0, -'/assessments'.length);
}

async function readText(body: unknown, signal: AbortSignal): Promise<string | null> {
  if (body === null || body === undefined) return '';
  const reader = (body as ReadableStream<Uint8Array>).getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await abortable(reader.read(), signal);
      if (done) break;
      if (!(value instanceof Uint8Array)) return null;
      total += value.byteLength;
      if (total > MAX_BYTES) {
        discard(reader);
        return null;
      }
      chunks.push(value);
    }
  } catch (e) {
    discard(reader);
    throw e;
  }
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks));
  } catch {
    return null;
  }
}

export function createAssessmentApi(cfg: {
  secret: string;
  base: string | null;
  /** The siteverify URL, from which the other routes are derived. */
  endpoint?: string;
  timeoutMs: number;
  fetchImpl: typeof fetch;
}): AssessmentApi {
  const { secret, base, timeoutMs, fetchImpl } = cfg;
  const root = cfg.endpoint === undefined ? null : v1Root(cfg.endpoint);

  async function send(url: string, payload: unknown): Promise<unknown> {
    const signal = AbortSignal.timeout(timeoutMs);
    let status: number;
    let retryAfter: string | null = null;
    let text: string | null;
    try {
      const res = (await abortable(
        Promise.resolve(
          fetchImpl(url, {
            method: 'POST',
            headers: {
              authorization: `Bearer ${secret}`,
              'content-type': 'application/json',
              accept: 'application/json',
            },
            body: JSON.stringify(payload),
            redirect: 'manual',
            signal,
          }),
        ),
        signal,
        (late) => discard((late as { body?: unknown } | null | undefined)?.body),
      )) as Response | null;
      if (typeof res !== 'object' || res === null) throw new RevokeGPTError('network-error', 0);
      status = res.status;
      retryAfter = res.headers?.get?.('retry-after') ?? null;
      text = await readText(res.body, signal);
    } catch (e) {
      if (e instanceof RevokeGPTError) throw e;
      throw new RevokeGPTError('network-error', 0);
    }
    let parsed: unknown;
    try {
      parsed = text === null ? undefined : JSON.parse(text);
    } catch {
      parsed = undefined;
    }
    if (status < 200 || status > 299) {
      const err = (parsed as { error?: { code?: unknown; requestId?: unknown } } | undefined)
        ?.error;
      const code = typeof err?.code === 'string' ? err.code : 'internal-error';
      const secs =
        retryAfter !== null && /^\d{1,6}$/.test(retryAfter) ? Number(retryAfter) : undefined;
      const extra = {
        ...(typeof err?.requestId === 'string' ? { requestId: err.requestId } : {}),
        ...(secs !== undefined ? { retryAfterSeconds: secs } : {}),
      };
      if (status === 503) throw new RevokeGPTUnavailable(extra);
      throw new RevokeGPTError(code, status, extra);
    }
    if (status !== 200 || parsed === undefined)
      throw new RevokeGPTError('invalid-response', status);
    return parsed;
  }

  function requireBase(): string {
    if (base === null) throw new TypeError('assessments need an endpoint that ends in /siteverify');
    return base;
  }

  function requireRoot(): string {
    if (root === null) throw new TypeError('this call needs an endpoint that ends in /siteverify');
    return root;
  }

  /** Validates `value` against a protocol schema; the message never includes the value. */
  function check<T>(
    schema: { safeParse(v: unknown): { success: boolean; data?: T } },
    value: unknown,
    what: string,
  ): T {
    const r = schema.safeParse(value);
    if (!r.success) throw new TypeError(`invalid ${what}`);
    return r.data as T;
  }

  return {
    async createAssessment(input) {
      const b = requireBase();
      if (typeof input !== 'object' || input === null) throw new TypeError('invalid input');
      const event: Record<string, unknown> = {};
      for (const k of [
        'token',
        'expectedAction',
        'express',
        'userIpAddress',
        'userAgent',
        'headers',
        'fraudPrevention',
      ] as const)
        if (Object.hasOwn(input, k) && input[k] !== undefined) event[k] = input[k];
      const request: Record<string, unknown> = { event };
      if (Object.hasOwn(input, 'userInfo') && input.userInfo !== undefined) {
        const u = input.userInfo as UserInfoInput;
        if (typeof u !== 'object' || u === null) throw new TypeError('invalid userInfo');
        const wire = ownCopy(u);
        const t = wire.createAccountTime;
        if (t instanceof Date) {
          if (Number.isNaN(t.getTime())) throw new TypeError('invalid userInfo');
          wire.createAccountTime = t.toISOString();
        }
        if (
          wire.accountId === undefined &&
          wire.hashedAccountId === undefined &&
          wire.userIds === undefined
        )
          throw new TypeError('userInfo needs accountId, hashedAccountId or userIds');
        event.userInfo = check(UserInfo, wire, 'userInfo');
      }
      if (Object.hasOwn(input, 'transactionData') && input.transactionData !== undefined)
        event.transactionData = checkTransactionData(input.transactionData);
      if (Object.hasOwn(input, 'accountVerification') && input.accountVerification !== undefined) {
        if (event.userInfo === undefined || !hasAccount(event.userInfo))
          throw new TypeError('accountVerification needs a named account in userInfo');
        const v = input.accountVerification as AccountVerificationInput;
        if (typeof v !== 'object' || v === null) throw new TypeError('invalid accountVerification');
        request.accountVerification = check(
          AccountVerificationRequest,
          ownCopy(v),
          'accountVerification',
        );
      }
      const body = await send(b, request);
      const r = AssessmentSchema.safeParse(body);
      if (!r.success) throw new RevokeGPTError('invalid-response', 200);
      return r.data;
    },
    async annotate(aidOrName, input = {}) {
      const b = requireBase();
      if (typeof aidOrName !== 'string') throw new TypeError('invalid assessment id');
      const aid = aidOrName.startsWith('assessments/') ? aidOrName.slice(12) : aidOrName;
      if (!AID_RE.test(aid)) throw new TypeError('invalid assessment id');
      if (typeof input !== 'object' || input === null) throw new TypeError('invalid input');
      const payload = ownCopy(input);
      const reason = (payload.transactionEvent as { reason?: unknown } | undefined)?.reason;
      if (typeof reason === 'string') scanForPan(reason);
      await send(`${b}/${aid}:annotate`, check(AnnotateRequest, payload, 'annotate input'));
    },
    async eraseAccount(input) {
      const r = requireRoot();
      if (typeof input !== 'object' || input === null) throw new TypeError('invalid input');
      await send(`${r}/accounts:erase`, check(EraseRequest, ownCopy(input), 'erase input'));
    },
  };
}
