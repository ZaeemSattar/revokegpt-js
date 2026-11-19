// Internal module: NOT re-exported from src/index.ts, and unreachable through the package's
// `exports` map. These are the regex instances the functional validators (`isSiteKey`,
// `parseSecretKey`, `canonicalizeHostname`, ...) use. Every public `*_RE` export is a copy made with
// `copyRegex`, so mutating an exported regex (for example with `RegExp.prototype.compile`) cannot
// change what those validators accept. Every zod schema gets its own copy too, but a schema's copy
// stays reachable through Zod's internals (`_zod.def`): the schemas follow Zod's object model, and
// in-process code execution is outside this library's threat model.
//
// Every pattern must match the whole string: `^` and `$` without the `m` flag, so in JavaScript `$`
// never matches before a trailing newline. Ports to engines where `$` does (Python `re.match`, PHP
// without `D`, Java `find`) must anchor with `\A`/`\z` (or equivalent) instead.

/** `action`: 1 to 100 characters from `A-Z a-z 0-9 / _`. */
export const ACTION = /^[A-Za-z0-9/_]{1,100}$/;
/** `cdata`: 0 to 255 characters from `A-Z a-z 0-9 _ -`. */
export const CDATA = /^[A-Za-z0-9_-]{0,255}$/;
/** `sdk.name`: 1 to 40 characters from `a-z 0-9 @ / . _ -` (npm-style names, lowercase). */
export const SDK_NAME = /^[a-z0-9@/._-]{1,40}$/;
/** `sdk.version`: 1 to 40 characters from `0-9 A-Z a-z . + -` (semver-style). */
export const SDK_VERSION = /^[0-9A-Za-z.+-]{1,40}$/;
/** Unpadded base64url alphabet, one or more characters (shape only). */
export const BASE64URL = /^[A-Za-z0-9_-]+$/;
/**
 * Letter-digit-hyphen labels of 1 to 63 characters joined by dots. No lookahead, so it compiles in
 * RE2 and other engines without lookaround; the 253-character total is checked separately.
 */
export const HOSTNAME_LABELS =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
/** See `HOSTNAME_FORBIDDEN_RE` in hostname.ts for the documented code-point list. */
export const HOSTNAME_FORBIDDEN =
  // biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are intentionally rejected
  /[\u0000-\u0020\u007f-\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff/?#@:\\%*]/;
export const SITE_KEY = /^rgpk_[0-9A-Za-z]{20}$/;
/**
 * Siteverify `response`: a token, 1 to 2048 (`TOKEN_MAX_LENGTH`) characters of the unpadded
 * base64url alphabet. So a string built by concatenation (`x&secret=...`, `x","secret":"...`) is
 * never a well-formed `response` (red-team round 2, A-1).
 */
export const RESPONSE_TOKEN = /^[A-Za-z0-9_-]{1,2048}$/;
/** A site id: the site's UUID in lowercase canonical text form (36 characters). */
export const SITE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/**
 * Siteverify `challenge_ts`: an RFC 3339 date-time with `Z` or a numeric offset, exactly what
 * `z.iso.datetime({ offset: true })` accepts, but spelled with `[0-9]` instead of `\d`, so a port to
 * an engine where `\d` matches non-ASCII digits (Python 3 `re` on str, .NET) cannot widen it.
 */
export const DATE_TIME =
  /^(?:(?:[0-9][0-9][2468][048]|[0-9][0-9][13579][26]|[0-9][0-9]0[48]|[02468][048]00|[13579][26]00)-02-29|[0-9]{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12][0-9]|3[01])|(?:0[469]|11)-(?:0[1-9]|[12][0-9]|30)|(?:02)-(?:0[1-9]|1[0-9]|2[0-8])))T(?:(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]+)?(?:Z|([+-](?:[01][0-9]|2[0-3]):[0-5][0-9])))$/;
/**
 * An Android package name (applicationId): two or more dot-separated segments, each a letter
 * followed by letters, digits or `_`. The 255-character maximum is checked separately.
 */
export const ANDROID_PACKAGE = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/;
/**
 * An iOS bundle id: two or more dot-separated segments of `A-Z a-z 0-9 -`. The 155-character
 * maximum is checked separately.
 */
export const IOS_BUNDLE_ID = /^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/;
/** A Play Integrity token: JWE compact serialization in `A-Z a-z 0-9 _ . = -`, one or more. */
export const PLAY_INTEGRITY_TOKEN = /^[A-Za-z0-9_.=-]+$/;
/**
 * Canonical standard base64 (RFC 4648 section 4) with padding: the unused low bits of the last
 * character before the padding are zero, so one byte string has one spelling. It also matches the
 * empty string; a minimum length is checked separately.
 */
export const BASE64_PADDED =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?$/;
/** An App Attest key id: canonical padded standard base64 of 32 bytes (44 characters). */
export const APP_ATTEST_KEY_ID = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;
/** A `hashedAccountId` (protocol v1 section 15): canonical padded standard base64 of exactly 32 bytes (44 characters). */
export const HASHED_ACCOUNT_ID = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;
/** Canonical unpadded base64url of exactly 16 bytes (22 characters): a session id or a truncated hash. */
export const BASE64URL_16 = /^[A-Za-z0-9_-]{21}[AQgw]$/;
/** A one-time code: exactly six ASCII digits (section 17). */
export const OTP_CODE = /^[0-9]{6}$/;
/** An email address as a shape check only: one `@`, no whitespace, local part 1 to 64 and domain 1 to 189 characters (254 in all). */
export const EMAIL_ADDRESS = /^[^@ \t\r\n]{1,64}@[^@ \t\r\n]{1,189}$/;
/** An E.164 phone number: `+`, a non-zero digit, then 6 to 14 digits. */
export const E164 = /^\+[1-9][0-9]{6,14}$/;
/** A BCP 47 language code, shape only (for example `en`, `pt-BR`, `zh-Hant-TW`). */
export const LANGUAGE_CODE = /^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}$/;
/** An assessment id: 42 base64url characters (the `aid` of `assessments/<aid>`, section 14). */
export const ASSESSMENT_ID = /^[A-Za-z0-9_-]{42}$/;
export const SECRET_KEY = /^(rgsk|rgmk)_([0-9A-Za-z]{12})_([0-9A-Za-z]{32})([0-9A-Za-z]{6})$/;

/** A new, independent RegExp with the same source and flags. */
export function copyRegex(re: RegExp): RegExp {
  return new RegExp(re.source, re.flags);
}
