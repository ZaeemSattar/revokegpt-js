import { fromBase64Url, toBase64Url } from './base64url.js';
import { copyRegex, HASHED_ACCOUNT_ID } from './patterns.js';
import { canonicalUsername } from './username.js';

/**
 * Account protection primitives (protocol v1 sections 9 and 15): the keyed hashes that stand in for
 * an account id, an endpoint and a device, so no raw identifier is stored, logged or put in a name.
 */

/** Account labels in the order a response lists them. An open enum: clients MUST tolerate unknown values. */
export const ACCOUNT_LABELS = Object.freeze([
  'PROFILE_MATCH',
  'SUSPICIOUS_LOGIN_ACTIVITY',
  'SUSPICIOUS_ACCOUNT_CREATION',
  'RELATED_ACCOUNTS_NUMBER_HIGH',
  // Our extension; Google's enum has no such label.
  'CREDENTIAL_STUFFING_SUSPECTED',
] as const);
export type AccountLabel = (typeof ACCOUNT_LABELS)[number];

/** Account verification results: `RESULT_UNSPECIFIED` and the seven values this service emits. */
export const VERIFICATION_RESULTS = Object.freeze([
  'RESULT_UNSPECIFIED',
  'SUCCESS_USER_VERIFIED',
  'ERROR_USER_NOT_VERIFIED',
  'ERROR_RECIPIENT_NOT_ALLOWED',
  'ERROR_RECIPIENT_ABUSE_LIMIT_EXHAUSTED',
  'ERROR_CUSTOMER_QUOTA_EXHAUSTED',
  'ERROR_SITE_ONBOARDING_INCOMPLETE',
  'ERROR_CRITICAL_INTERNAL',
] as const);
export type VerificationResult = (typeof VERIFICATION_RESULTS)[number];

/** HKDF info prefixes: `<prefix><siteId>`. The info is the domain separation between the three keys. */
export const ACCOUNT_KEY_INFO = Object.freeze({
  account: 'rg-acct-v1|',
  endpoint: 'rg-ep-v1|',
  device: 'rg-dev-v1|',
} as const);

/** Tag byte of the account hash input: a raw `accountId` (ASCII `a`) or a `hashedAccountId` (ASCII `h`). */
export const ACCT_TAG = Object.freeze({ raw: 0x61, hashed: 0x68 } as const);

/** The raw `accountId` limit, in UTF-8 bytes. */
export const ACCOUNT_ID_MAX_BYTES = 256;
/** A `hashedAccountId` is exactly this many bytes. */
export const HASHED_ACCOUNT_ID_BYTES = 32;
/** The account and endpoint hash keeps this many bytes of the HMAC (22 base64url characters). */
export const ACCT_HASH_BYTES = 16;
/** The device hash `dv` keeps this many bytes of the HMAC (11 base64url characters). */
export const DEVICE_HASH_BYTES = 8;

/** A public copy: a canonical padded standard base64 `hashedAccountId` of 32 bytes. */
export const HASHED_ACCOUNT_ID_RE: RegExp = copyRegex(HASHED_ACCOUNT_ID);

const enc = new TextEncoder();
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

/**
 * Derives a 32-byte HMAC-SHA-256 key with HKDF-SHA-256 (salt empty, L = 32) from a 32-byte master
 * key and an info string, for example `rg-acct-v1|<siteId>` from `ACCOUNT_KEY`. The key is not
 * extractable.
 */
export async function deriveSiteKey(master: Uint8Array, info: string): Promise<CryptoKey> {
  if (!(master instanceof Uint8Array) || master.length !== 32)
    throw new RangeError('master key must be 32 bytes');
  if (typeof info !== 'string' || info.length === 0) throw new TypeError('info must be a string');
  const ikm = await crypto.subtle.importKey('raw', new Uint8Array(master), 'HKDF', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(info) },
    ikm,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign'],
  );
}

async function hmacPrefix(
  k: CryptoKey,
  input: Uint8Array<ArrayBuffer>,
  bytes: number,
): Promise<string> {
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', k, input));
  return toBase64Url(mac.subarray(0, bytes));
}

/**
 * The account hash: `base64url(HMAC(K_site, tag || input)[0..16])`, 22 characters. Pass exactly one
 * of `accountId` (UTF-8, 1 to 256 bytes) and `hashedAccountId` (32 bytes). The tag keeps a raw id and
 * a pre-hashed one apart, so the same bytes never give the same hash.
 */
export async function acctHash(
  k: CryptoKey,
  input: { accountId: string } | { hashedAccountId: Uint8Array },
): Promise<string> {
  const hasRaw = 'accountId' in input && input.accountId !== undefined;
  const hasHashed = 'hashedAccountId' in input && input.hashedAccountId !== undefined;
  if (hasRaw === hasHashed) throw new TypeError('exactly one of accountId and hashedAccountId');
  let tag: number;
  let body: Uint8Array<ArrayBuffer>;
  if (hasRaw) {
    const id = (input as { accountId: string }).accountId;
    if (typeof id !== 'string' || LONE_SURROGATE.test(id))
      throw new TypeError('accountId must be a well-formed string');
    body = enc.encode(id);
    if (body.length < 1 || body.length > ACCOUNT_ID_MAX_BYTES)
      throw new RangeError('accountId must be 1 to 256 bytes');
    tag = ACCT_TAG.raw;
  } else {
    const h = (input as { hashedAccountId: Uint8Array }).hashedAccountId;
    if (!(h instanceof Uint8Array) || h.length !== HASHED_ACCOUNT_ID_BYTES)
      throw new RangeError('hashedAccountId must be 32 bytes');
    body = new Uint8Array(h);
    tag = ACCT_TAG.hashed;
  }
  const msg = new Uint8Array(1 + body.length);
  msg[0] = tag;
  msg.set(body, 1);
  return hmacPrefix(k, msg, ACCT_HASH_BYTES);
}

/**
 * The endpoint hash (key from info `rg-ep-v1|<siteId>`): `base64url(HMAC(K_ep, UTF-8 of the
 * canonical endpoint)[0..16])`. The endpoint is canonicalized with `canonicalUsername`, so case and
 * a `+tag` do not make a second mailbox in the per-endpoint abuse limits.
 */
export async function endpointHash(k: CryptoKey, endpoint: string): Promise<string> {
  if (typeof endpoint !== 'string' || endpoint.length === 0 || endpoint.length > 320)
    throw new RangeError('endpoint must be 1 to 320 characters');
  if (LONE_SURROGATE.test(endpoint)) throw new TypeError('endpoint must be a well-formed string');
  return hmacPrefix(k, enc.encode(canonicalUsername(endpoint)), ACCT_HASH_BYTES);
}

/**
 * Mailbox providers whose addresses have equivalent spellings, as `domain -> [canonical domain,
 * whether dots in the local part are ignored]`. Extensible: add a provider only when its aliasing
 * is documented and stable. A `+tag` is dropped for every domain.
 */
export const MAILBOX_ALIAS_PROVIDERS: Readonly<Record<string, readonly [string, boolean]>> =
  Object.freeze({
    'gmail.com': ['gmail.com', true],
    'googlemail.com': ['gmail.com', true],
  });

/**
 * The MFA-only canonical mailbox, the input of the per-recipient session caps: NFKC, trim,
 * lowercase; the `+tag` dropped from the local part (unless that empties it); and, for the
 * providers in `MAILBOX_ALIAS_PROVIDERS`, dots removed from the local part and the domain mapped to
 * its canonical one. The address a code is sent to is never this value. A string without exactly
 * one `@` is returned lowercased and trimmed.
 */
export function canonicalMailbox(address: string): string {
  const s = canonicalUsername(address);
  const at = s.indexOf('@');
  if (at < 0 || s.indexOf('@', at + 1) >= 0) return s;
  let local = s.slice(0, at);
  let domain = s.slice(at + 1);
  const provider = MAILBOX_ALIAS_PROVIDERS[domain];
  if (provider !== undefined) {
    domain = provider[0];
    if (provider[1]) local = local.replaceAll('.', '');
  }
  return local.length === 0 ? s : `${local}@${domain}`;
}

/** The five device inputs: WebGL renderer, platform, hardware concurrency, first language, time zone. */
export type DeviceParts = [
  string | null,
  string | null,
  number | null,
  string | null,
  string | null,
];

/**
 * The device hash `dv`: `base64url(HMAC(K_dev, UTF-8 of JSON.stringify(parts))[0..8])`, 11
 * characters. A missing value is `null`. Canvas is not an input (it is noisy under Brave and
 * resist-fingerprinting).
 */
export async function deviceHash(k: CryptoKey, parts: DeviceParts): Promise<string> {
  if (!Array.isArray(parts) || parts.length !== 5)
    throw new RangeError('parts must have 5 elements');
  const [gl, platform, cores, lang, tz] = parts;
  for (const s of [gl, platform, lang, tz])
    if (s !== null && (typeof s !== 'string' || s.length > 512 || LONE_SURROGATE.test(s)))
      throw new TypeError('device parts must be strings of at most 512 characters, or null');
  if (cores !== null && !(Number.isSafeInteger(cores) && cores >= 0))
    throw new TypeError('hardwareConcurrency must be a non-negative integer or null');
  const json = JSON.stringify([gl, platform, cores, lang, tz]);
  return hmacPrefix(k, enc.encode(json), DEVICE_HASH_BYTES);
}

/** Decodes a `hashedAccountId` (canonical padded standard base64 of 32 bytes); null for anything else. */
export function decodeHashedAccountId(s: unknown): Uint8Array | null {
  if (typeof s !== 'string' || !HASHED_ACCOUNT_ID_RE.test(s)) return null;
  // The pattern is canonical, so this strict base64url decode of the 43 data characters cannot throw.
  const bytes = fromBase64Url(s.slice(0, 43).replaceAll('+', '-').replaceAll('/', '_'));
  return bytes.length === HASHED_ACCOUNT_ID_BYTES ? bytes : null;
}
