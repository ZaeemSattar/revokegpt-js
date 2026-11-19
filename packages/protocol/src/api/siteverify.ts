import { z } from 'zod';
import { isAppId } from '../attest.js';
import { TOKEN_MAX_LENGTH } from '../constants.js';
import { SITEVERIFY_ERROR_CODES } from '../errors.js';
import { canonicalizeHostname } from '../hostname.js';
import { canonicalizeIp } from '../ip.js';
import { MODES } from '../modes.js';
import { copyRegex, DATE_TIME, RESPONSE_TOKEN } from '../patterns.js';
import { REASON_CODES } from '../reasons.js';
import { type AppRef, SiteKey } from './common.js';

/**
 * The OpenAPI `pattern` for an IPv6 `remoteip`: exactly the addresses zod's `z.ipv6()` accepts at
 * runtime (the WHATWG URL IPv6 parser over `[0-9A-Fa-f:.]`), including an embedded IPv4 tail such
 * as the IPv4-mapped `::ffff:192.0.2.1`. Zod's own JSON-schema pattern omits IPv4 tails, so it is
 * replaced. Eight 1-4 digit hex groups, where `::` stands for one or more zero groups and a
 * dotted-quad tail (decimal octets 0-255, no leading zeros) counts as two. One alternative per
 * number of groups before `::`, so the pattern needs no lookaround (RE2-portable).
 */
const IPV6_PATTERN = (() => {
  const h = '[0-9a-fA-F]{1,4}';
  const octet = '(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])';
  const v4 = `${octet}(?:\\.${octet}){3}`;
  /** `left` groups, then `::`, then up to `maxRight` groups, then `tail` (if any). */
  const compressed = (left: number, maxRight: number, tail = '') => {
    const head = left === 0 ? '::' : left === 1 ? `${h}::` : `(?:${h}:){${left}}:`;
    if (tail) return maxRight === 0 ? `${head}${tail}` : `${head}(?:${h}:){0,${maxRight}}${tail}`;
    if (maxRight === 0) return head;
    if (maxRight === 1) return `${head}(?:${h})?`;
    return `${head}(?:${h}(?::${h}){0,${maxRight - 1}})?`;
  };
  const alternatives = [`(?:${h}:){7}${h}`, `(?:${h}:){6}${v4}`];
  for (let left = 0; left <= 7; left++) alternatives.push(compressed(left, 7 - left));
  for (let left = 0; left <= 5; left++) alternatives.push(compressed(left, 5 - left, v4));
  return `^(?:${alternatives.join('|')})$`;
})();

/** The OpenAPI `pattern` for an IPv4 `remoteip`: strict dotted decimal, no leading zeros. */
const IPV4_PATTERN = (() => {
  const octet = '(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])';
  return `^(?:${octet}\\.){3}${octet}$`;
})();

const REMOTE_IP_DESCRIPTION =
  'End-user IP address: IPv4 (dotted decimal) or IPv6, including IPv4-mapped forms such as ::ffff:192.0.2.1.';

/**
 * An IPv4 or IPv6 address (no zone id, no brackets, no surrounding whitespace), decided by
 * `canonicalizeIp` alone (campaign round 4 F13, RT4-X-3). Until F12 the schema was zod's
 * `z.ipv4()`/`z.ipv6()` union, and `z.ipv6()` asks the runtime's URL parser: Bun's accepted
 * `::5A0:` (RT3-A-4) and rejects valid text with an IPv4 tail such as `1:2:3:4::1.2.3.4`. Now no URL
 * parser is consulted, so acceptance is `canonicalizeIp(v) !== null` on every runtime, as protocol
 * v1 section 10 states. The OpenAPI document keeps the IPv4 and IPv6 alternatives with their
 * patterns (byte-identical to F12; the patterns accept exactly what `canonicalizeIp` accepts, pinned
 * by `openapi.test.ts`), written by the override below.
 *
 * Campaign round 5 F14 (RT5-X-8): the same `anyOf` and description are also plain metadata, so
 * zod's own `z.toJSONSchema` carries the patterns too (it copies metadata keys onto
 * `{"type":"string"}`, which it used to emit alone). zod-openapi applies the override last, so the
 * OpenAPI document is unchanged.
 */
const remoteIpJsonSchema = () => ({
  anyOf: [
    { type: 'string', format: 'ipv4', pattern: IPV4_PATTERN },
    { type: 'string', format: 'ipv6', pattern: IPV6_PATTERN },
  ],
  description: REMOTE_IP_DESCRIPTION,
});
const RemoteIp = z
  .string()
  .refine((v) => canonicalizeIp(v) !== null, { message: 'Invalid IP address' })
  .meta({
    ...remoteIpJsonSchema(),
    // Typed here: the zod-openapi augmentation of `.meta` is loaded only by the build-time
    // src/openapi.ts, which the published build excludes.
    override: ({ jsonSchema }: { jsonSchema: Record<string, unknown> }) => {
      for (const key of Object.keys(jsonSchema)) delete jsonSchema[key];
      Object.assign(jsonSchema, remoteIpJsonSchema());
    },
  });

/**
 * Compat `remoteip`: a valid address is kept; anything else (wrong type, malformed, control
 * characters) becomes undefined instead of failing the request, as existing server libraries may
 * send a value we would reject.
 */
const compatRemoteIpJsonSchema = () => ({
  type: 'string',
  description: 'End-user IP address (IPv4 or IPv6). An invalid value is ignored, not rejected.',
});
// F14 (RT5-X-8): plain metadata as well, for zod's own `z.toJSONSchema`, which copied the object
// override in as an `override` keyword; the function override keeps the OpenAPI bytes.
const CompatRemoteIp = z
  .unknown()
  .transform((v): string | undefined => (RemoteIp.safeParse(v).success ? (v as string) : undefined))
  .meta({
    ...compatRemoteIpJsonSchema(),
    override: ({ jsonSchema }: { jsonSchema: Record<string, unknown> }) => {
      for (const key of Object.keys(jsonSchema)) delete jsonSchema[key];
      Object.assign(jsonSchema, compatRemoteIpJsonSchema());
    },
  });

const siteverifyRequestShape = {
  secret: z.string().min(1).max(128),
  response: z.string().min(1).max(TOKEN_MAX_LENGTH).regex(copyRegex(RESPONSE_TOKEN)).meta({
    description:
      'The response token: 1 to 2048 characters of unpadded base64url (`A-Z a-z 0-9 - _`).',
  }),
  sitekey: SiteKey.optional(),
};

/**
 * `/v1/siteverify` request body: unknown fields are rejected, and `remoteip` must be a valid IPv4
 * or IPv6 address. There is no idempotency key in v1: every verification of a token after the
 * first fails with `timeout-or-duplicate`.
 */
export const SiteverifyRequest = z.strictObject({
  ...siteverifyRequestShape,
  remoteip: RemoteIp.optional(),
});
export type SiteverifyRequest = z.infer<typeof SiteverifyRequest>;

/**
 * `/recaptcha/api/siteverify` request body: the same known fields and bounds, but unknown fields
 * (such as `version` sent by existing server libraries) are stripped instead of rejected, and an
 * invalid `remoteip` is dropped (undefined) instead of rejected.
 */
export const SiteverifyCompatRequest = z.object({
  ...siteverifyRequestShape,
  remoteip: CompatRemoteIp.optional(),
});
export type SiteverifyCompatRequest = z.infer<typeof SiteverifyCompatRequest>;

export const SiteverifyResponse = z.looseObject({
  success: z.boolean(),
  // The runtime check is Zod's; the OpenAPI pattern is the same regex spelled with [0-9] (RT2-A-6).
  challenge_ts: z.iso
    .datetime({ offset: true })
    .meta({ override: { pattern: DATE_TIME.source } })
    .optional(),
  hostname: z.string().optional(),
  apk_package_name: z.string().optional(),
  ios_bundle_id: z.string().optional(),
  score: z.number().min(0).max(1).optional(),
  action: z.string().optional(),
  cdata: z.string().optional(),
  mode: z
    .string()
    .optional()
    .meta({ description: `Known values: ${MODES.join(', ')}. Clients must tolerate new values.` }),
  reasons: z
    .array(z.string())
    .optional()
    .meta({
      description: `Known values: ${REASON_CODES.join(', ')}. Clients must tolerate new values.`,
    }),
  'error-codes': z
    .array(z.string())
    .optional()
    .meta({
      description: `Known values: ${SITEVERIFY_ERROR_CODES.join(', ')}. Clients must tolerate new values.`,
    }),
});
export type SiteverifyResponse = z.infer<typeof SiteverifyResponse>;

/** What a relying party reads from a siteverify response. Gate on `verified` alone. */
export type SiteverifyResult = {
  /** True only for a well-formed response body whose `success` is the boolean `true`. */
  verified: boolean;
  score: number | null;
  action: string | null;
  hostname: string | null;
  errorCodes: string[];
  reasons: string[];
  /**
   * Android app package name from `apk_package_name`, or `null` when the body does not carry it.
   * Always an own property (campaign round 3 F12, RT3-A-3: when it was left off, a polluted
   * `Object.prototype.apkPackageName` was read through the result).
   */
  apkPackageName: string | null;
  /** iOS bundle id from `ios_bundle_id`, or `null` when the body does not carry it. Always own. */
  iosBundleId: string | null;
};

const notVerified = (): SiteverifyResult => ({
  verified: false,
  score: null,
  action: null,
  hostname: null,
  errorCodes: [],
  reasons: [],
  apkPackageName: null,
  iosBundleId: null,
});

/** `obj[key]` if `key` is an own property of `obj`, else undefined (never an inherited value). */
function own(obj: object, key: string): unknown {
  return Object.hasOwn(obj, key) ? (obj as Record<string, unknown>)[key] : undefined;
}

const STRING_FIELDS = [
  'hostname',
  'action',
  'cdata',
  'mode',
  'apk_package_name',
  'ios_bundle_id',
] as const;
const STRING_ARRAY_FIELDS = ['reasons', 'error-codes'] as const;

const isStringArray = (v: unknown): v is string[] =>
  Array.isArray(v) && v.every((x) => typeof x === 'string');

/**
 * Plain-JavaScript check of every known field of a response body (`copy` is a null-prototype copy
 * of the body's own properties), independent of Zod: a Zod schema can be made to skip its checks
 * from outside (for example by `Object.prototype.skipChecks` or `Object.prototype.memo`), so the
 * known fields are checked again after `safeParse`. An absent or `undefined` field is allowed.
 */
function knownFieldsValid(copy: Record<string, unknown>): boolean {
  if (typeof copy.success !== 'boolean') return false;
  for (const k of STRING_FIELDS) {
    const v = copy[k];
    if (v !== undefined && typeof v !== 'string') return false;
  }
  for (const k of STRING_ARRAY_FIELDS) {
    const v = copy[k];
    if (v !== undefined && !isStringArray(v)) return false;
  }
  const score = copy.score;
  if (score !== undefined && !(typeof score === 'number' && score >= 0 && score <= 1)) return false;
  const ts = copy.challenge_ts;
  if (ts !== undefined && !(typeof ts === 'string' && DATE_TIME.test(ts))) return false;
  return true;
}

/**
 * Strict reading of a siteverify response (protocol v1, section 7). `body` is the raw response text
 * (a string, parsed once as JSON) or an already-parsed value. The result is "not verified" when the
 * text is not JSON, the value is not an object, any known field has the wrong type or range
 * (`SiteverifyResponse`, then a plain-JavaScript check of every known field that does not depend on
 * Zod), or `success` is anything other than the boolean `true` (so `"false"`,
 * `1`, `[false]` and a missing `success` all fail closed). Only the body's own enumerable
 * properties are read: they are copied onto a null-prototype object before validation, so a
 * polluted `Object.prototype` (or any other prototype) cannot supply `success`, `score`,
 * `hostname` or any other field. The result is a plain object whose eight fields are always own
 * properties (`null`, or `[]` for the two arrays, when absent), so nothing is read through its
 * prototype either. Never throws.
 */
export function parseSiteverifyResult(body: unknown): SiteverifyResult {
  try {
    const value: unknown = typeof body === 'string' ? JSON.parse(body) : body;
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return notVerified();
    const copy: Record<string, unknown> = Object.create(null);
    for (const key of Object.keys(value)) copy[key] = (value as Record<string, unknown>)[key];
    const parsed = SiteverifyResponse.safeParse(copy);
    if (!parsed.success || !knownFieldsValid(copy)) return notVerified();
    // Values come from the own-property copy, already checked by hand (not from Zod's output).
    const score = own(copy, 'score') as number | undefined;
    const action = own(copy, 'action') as string | undefined;
    const hostname = own(copy, 'hostname') as string | undefined;
    const errorCodes = own(copy, 'error-codes') as string[] | undefined;
    const reasons = own(copy, 'reasons') as string[] | undefined;
    const apk = own(copy, 'apk_package_name') as string | undefined;
    const ios = own(copy, 'ios_bundle_id') as string | undefined;
    // Every field is an own property of a plain object (never left off, never inherited).
    return {
      verified: Object.hasOwn(copy, 'success') && copy.success === true,
      score: score ?? null,
      action: action ?? null,
      hostname: hostname ?? null,
      errorCodes: [...(errorCodes ?? [])],
      reasons: [...(reasons ?? [])],
      apkPackageName: apk ?? null,
      iosBundleId: ios ?? null,
    };
  } catch {
    // Not JSON, or a parsed value whose property getters throw.
    return notVerified();
  }
}

/** What a relying party expects of a verified result (protocol v1 section 7). */
export type SiteverifyExpectation = {
  /** The action this endpoint serves. Omitted: only a token without an action passes. */
  action?: string;
  /** Threshold in [0, 1]. Required whenever the result carries a score. */
  minScore?: number;
} & (
  | {
      /** The hostname the token must carry, already canonical, compared exactly (web flow). */
      hostname: string;
      app?: undefined;
    }
  | {
      /**
       * The app the token must carry (app flow, M3): `apkPackageName` for `android`,
       * `iosBundleId` for `ios`, compared exactly. The id must be well formed (`isAppId`).
       */
      app: AppRef;
      hostname?: undefined;
    }
);

export type SiteverifyCheckReason =
  | 'invalid-expectation'
  | 'not-verified'
  | 'hostname-mismatch'
  | 'app-mismatch'
  | 'action-mismatch'
  | 'score-missing'
  | 'score-invalid'
  | 'threshold-missing'
  | 'score-below-threshold';

export type SiteverifyCheck = { ok: boolean; reason?: SiteverifyCheckReason };

const fail = (reason: SiteverifyCheckReason): SiteverifyCheck => ({ ok: false, reason });

/**
 * The relying-party check of protocol v1 section 7 ("Relying-party verification"), on a result from
 * `parseSiteverifyResult`. `expect` names exactly one of `hostname` (web) and `app` (native app).
 * `ok` is true only when all of these hold:
 * - `verified` is the boolean `true`;
 * - web: `hostname` is a string equal to `expect.hostname` (exact, no case folding or suffix
 *   match); app: `apkPackageName` (android) or `iosBundleId` (ios) is a string equal to
 *   `expect.app.id` (exact). A `null` app id is never a match, and the other platform's field
 *   never stands in;
 * - `action` equals `expect.action`, or both are absent (an expectation without an action accepts
 *   only a token without one, so a token minted for a lenient action cannot be spent on a strict
 *   endpoint);
 * - if the result carries a score, `expect.minScore` is set and `score >= minScore`; if
 *   `expect.minScore` is set, the result must carry a score in [0, 1].
 *
 * Otherwise `reason` says which check failed first: `hostname-mismatch` for a web expectation,
 * `app-mismatch` for an app one. An invalid expectation (both or neither of `hostname` and `app`; a
 * hostname that is not already canonical, `canonicalizeHostname(h) !== h`, such as `Shop.example`
 * or `shop.example.`; an `app` that is not an object whose `platform` is `android` or `ios` and
 * whose `id` is a well-formed id for it, `isAppId`; a non-string action; minScore not a number in
 * [0, 1]) gives `invalid-expectation`, never a pass. Only own properties of `result`, `expect` and
 * `expect.app` are read. Never throws.
 */
export function checkSiteverifyResult(
  result: SiteverifyResult,
  expect: SiteverifyExpectation,
): SiteverifyCheck {
  try {
    if (typeof expect !== 'object' || expect === null) return fail('invalid-expectation');
    const wantHost = own(expect, 'hostname');
    const wantApp = own(expect, 'app');
    const wantAction = own(expect, 'action');
    const minScore = own(expect, 'minScore');
    // Exactly one of hostname and app; `undefined` counts as absent, like an absent action.
    if ((wantHost === undefined) === (wantApp === undefined)) return fail('invalid-expectation');
    let appField: 'apkPackageName' | 'iosBundleId' | undefined;
    let appId: string | undefined;
    if (wantApp !== undefined) {
      if (typeof wantApp !== 'object' || wantApp === null || Array.isArray(wantApp))
        return fail('invalid-expectation');
      const platform = own(wantApp, 'platform');
      const id = own(wantApp, 'id');
      if (!isAppId(platform, id)) return fail('invalid-expectation');
      appField = platform === 'android' ? 'apkPackageName' : 'iosBundleId';
      appId = id as string;
    } else if (typeof wantHost !== 'string' || canonicalizeHostname(wantHost) !== wantHost)
      return fail('invalid-expectation');
    if (wantAction !== undefined && typeof wantAction !== 'string')
      return fail('invalid-expectation');
    if (minScore !== undefined && !(typeof minScore === 'number' && minScore >= 0 && minScore <= 1))
      return fail('invalid-expectation');

    if (typeof result !== 'object' || result === null || Array.isArray(result))
      return fail('not-verified');
    if (own(result, 'verified') !== true) return fail('not-verified');
    if (appField !== undefined) {
      const got = own(result, appField);
      if (typeof got !== 'string' || got !== appId) return fail('app-mismatch');
    } else {
      const host = own(result, 'hostname');
      if (typeof host !== 'string' || host !== wantHost) return fail('hostname-mismatch');
    }
    const action = own(result, 'action') ?? null;
    if (wantAction === undefined ? action !== null : action !== wantAction)
      return fail('action-mismatch');
    const score = own(result, 'score') ?? null;
    if (score === null) return minScore === undefined ? { ok: true } : fail('score-missing');
    if (minScore === undefined) return fail('threshold-missing');
    if (!(typeof score === 'number' && score >= 0 && score <= 1)) return fail('score-invalid');
    return score >= minScore ? { ok: true } : fail('score-below-threshold');
  } catch {
    return fail('not-verified');
  }
}
