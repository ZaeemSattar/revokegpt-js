import type { z } from 'zod';
import { ChallengeResponse } from './api/challenge.js';
import type { PuzzleSpec, SolveResponse } from './api/solve.js';
import { SolveResponse as SolveResponseSchema } from './api/solve.js';
import { isAppId } from './attest.js';
import { hasDuplicateKeys } from './duplicates.js';
import { API_ERROR_CODES } from './errors.js';
import { isSiteKey } from './keys.js';
import { copyRegex, LANGUAGE_CODE, RESPONSE_TOKEN } from './patterns.js';

/**
 * The mobile SDK contract (protocol v1 section 23, M10): the message bridge between the hosted
 * challenge page and the native sheet, the page URL, the SDK error codes and the reference reading
 * of API responses. The native SDKs port `parsePageMessage` and `interpretApiResponse`; the vectors
 * `mobile-bridge.json` and `mobile-client.json` hold every port to this behaviour.
 */

/** The bridge version: the `rg` field of every message. */
export const BRIDGE_VERSION = 1;

/** The longest bridge message the native side parses (UTF-8 bytes of the text). */
export const BRIDGE_MAX_BYTES = 4096;

/** The longest API response body an SDK reads (bytes). */
export const MOBILE_RESPONSE_MAX_BYTES = 65536;

/** The longest `Retry-After` an SDK reports (seconds); a larger value is clamped. */
export const MOBILE_RETRY_AFTER_MAX_SECONDS = 3600;

/** A bridge message id: 1 to 64 characters of `A-Z a-z 0-9 _ -`. */
const ID = /^[A-Za-z0-9_-]{1,64}$/;
export const BRIDGE_ID_RE: RegExp = copyRegex(ID);
/** A page error code: 1 to 64 characters of `a-z 0-9 -`. */
const ERROR_CODE = /^[a-z0-9-]{1,64}$/;
export const BRIDGE_ERROR_CODE_RE: RegExp = copyRegex(ERROR_CODE);
/** The bridge height range in CSS pixels. */
export const BRIDGE_HEIGHT = Object.freeze({ min: 120, max: 2000 } as const);

/** The themes of the hosted page. */
export const BRIDGE_THEMES = Object.freeze(['light', 'dark', 'auto'] as const);
export type BridgeTheme = (typeof BRIDGE_THEMES)[number];

const TOKEN = copyRegex(RESPONSE_TOKEN);
const LOCALE = copyRegex(LANGUAGE_CODE);

/** Page to native. Strict: exactly these fields, no others. */
export type PageMessage =
  | { rg: 1; type: 'ready' }
  | { rg: 1; type: 'token'; id: string; token: string }
  | { rg: 1; type: 'error'; id: string; code: string }
  | { rg: 1; type: 'cancel'; id: string }
  | { rg: 1; type: 'height'; px: number };

/** Native to page. */
export type NativeMessage =
  | {
      rg: 1;
      type: 'puzzle';
      id: string;
      puzzle: PuzzleSpec;
      signalsKey: string;
      cid: string;
      locale: string;
      theme: BridgeTheme;
    }
  | { rg: 1; type: 'mfa'; id: string; requestToken: string; languageCode?: string };

const FIELDS: Readonly<Record<PageMessage['type'], readonly string[]>> = Object.freeze({
  ready: ['rg', 'type'],
  token: ['rg', 'type', 'id', 'token'],
  error: ['rg', 'type', 'id', 'code'],
  cancel: ['rg', 'type', 'id'],
  height: ['rg', 'type', 'px'],
});

const RG_TEXT = /"rg"\s*:\s*1\s*[,}]/;
const PX_TEXT = /"px"\s*:\s*(?:0|[1-9][0-9]*)\s*[,}]/;

const utf8Length = (s: string): number => new TextEncoder().encode(s).length;

/**
 * The reference reading of a page message, which the Swift and Kotlin validators and the page's own
 * copy must match (`mobile-bridge.json`). `raw` is either the message text (a string: at most
 * `BRIDGE_MAX_BYTES` UTF-8 bytes, well-formed JSON, no byte-order mark, no duplicate key) or the
 * object a platform bridge already decoded. The result is a fresh object holding only the known
 * fields, or `null` for anything else: a non-object, an array, a wrong `rg`, an unknown `type`, an
 * unknown or missing field (own keys only, so `__proto__` is an unknown key), a getter, an id or
 * token outside its charset or length, a `px` that is not an integer from 120 to 2000. Never throws.
 */
export function parsePageMessage(raw: unknown): PageMessage | null {
  try {
    let value: unknown = raw;
    if (typeof raw === 'string') {
      if (raw.length > BRIDGE_MAX_BYTES || utf8Length(raw) > BRIDGE_MAX_BYTES) return null;
      // Strict text (section 23.1): no escape of any kind, so a key, an id or a token is read the
      // same by every JSON parser; `rg` and `px` are plain integers in the text.
      if (raw.includes('\\')) return null;
      if (hasDuplicateKeys(raw, 'json')) return null;
      value = JSON.parse(raw);
      if (!RG_TEXT.test(raw)) return null;
      if ((value as { type?: unknown } | null)?.type === 'height' && !PX_TEXT.test(raw))
        return null;
    }
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
    const keys = Reflect.ownKeys(value);
    const get = (k: string): unknown => {
      const d = Object.getOwnPropertyDescriptor(value, k);
      return d && 'value' in d && d.enumerable ? d.value : undefined;
    };
    const type = get('type');
    if (typeof type !== 'string' || !Object.hasOwn(FIELDS, type)) return null;
    const allowed = FIELDS[type as PageMessage['type']];
    if (keys.length !== allowed.length) return null;
    for (const k of keys) if (typeof k !== 'string' || !allowed.includes(k)) return null;
    if (get('rg') !== BRIDGE_VERSION) return null;
    const id = get('id');
    const okId = typeof id === 'string' && ID.test(id);
    switch (type) {
      case 'ready':
        return { rg: 1, type: 'ready' };
      case 'token': {
        const token = get('token');
        if (!okId || typeof token !== 'string' || !TOKEN.test(token)) return null;
        return { rg: 1, type: 'token', id, token };
      }
      case 'error': {
        const code = get('code');
        if (!okId || typeof code !== 'string' || !ERROR_CODE.test(code)) return null;
        return { rg: 1, type: 'error', id, code };
      }
      case 'cancel':
        return okId ? { rg: 1, type: 'cancel', id } : null;
      case 'height': {
        const px = get('px');
        if (typeof px !== 'number' || !Number.isInteger(px)) return null;
        if (px < BRIDGE_HEIGHT.min || px > BRIDGE_HEIGHT.max) return null;
        return { rg: 1, type: 'height', px };
      }
      default:
        return null;
    }
  } catch {
    return null;
  }
}

/**
 * The longest native message text the page reads (UTF-8 bytes). Larger than `BRIDGE_MAX_BYTES`: a
 * puzzle message carries the sealed challenge (up to 4096 characters) and up to nine asset paths.
 */
export const NATIVE_MAX_BYTES = 16384;

/**
 * Every bridge message, in both directions, is JSON text (a string): the page posts
 * `JSON.stringify(message)`, and the SDK hands the page the text of its message (iOS: as the string
 * argument `m` of `callAsyncJavaScript`; Android: `JavaScriptReplyProxy.postMessage(text)`).
 */
export const BRIDGE_ENCODING = 'json-text';

/** The names the bridge is reached by in the page (section 23.1). */
export const BRIDGE_NAMES = Object.freeze({
  /** Android: the `WebViewCompat.addWebMessageListener` object, `window.revokegptNative`. */
  androidObject: 'revokegptNative',
  /** iOS: the script message handler, `window.webkit.messageHandlers.revokegpt`. */
  iosHandler: 'revokegpt',
  /** iOS: the page's receiver of native messages, `window.__rgNative(text)`. */
  iosReceiver: '__rgNative',
} as const);

/** The page's code for a lost puzzle group (`retry`): the SDK solves a fresh app challenge natively. */
export const PAGE_RETRY_CODE = 'puzzle-retry';
/** The page's code for "New puzzle", or a puzzle lost with its answer: the same. */
export const PAGE_NEW_PUZZLE_CODE = 'puzzle-new';
/**
 * The page-to-SDK codes that are not failures: on either one the SDK runs a fresh app challenge
 * (proof of work and attestation) and, on a puzzle, opens a new page. Never reported to the app.
 */
export const PAGE_RESOLVE_CODES = Object.freeze([PAGE_RETRY_CODE, PAGE_NEW_PUZZLE_CODE] as const);

/**
 * True when `s` is one JSON value in the strict text of section 23.1, applied to native messages:
 * well-formed, no backslash at all, no control character in a string, no duplicate key in any
 * object, and every number a plain non-negative integer (no sign, fraction, exponent or leading
 * zero). Linear, without recursion. Never throws.
 */
export function isStrictBridgeText(s: string): boolean {
  if (typeof s !== 'string' || s.includes('\\')) return false;
  const n = s.length;
  let i = 0;
  const stack: (Set<string> | null)[] = [];
  let state: 'value' | 'key' | 'after' = 'value';
  const isDigit = (c: number) => c >= 0x30 && c <= 0x39;
  const ws = () => {
    while (i < n) {
      const c = s.charCodeAt(i);
      if (c !== 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) return;
      i++;
    }
  };
  const str = (): string | null => {
    const start = ++i;
    for (; i < n; i++) {
      const c = s.charCodeAt(i);
      if (c === 0x22) return s.slice(start, i++);
      if (c < 0x20) return null;
    }
    return null;
  };
  for (;;) {
    ws();
    if (state === 'value') {
      const c = s.charCodeAt(i);
      if (c === 0x7b || c === 0x5b) {
        i++;
        ws();
        if (s.charCodeAt(i) === (c === 0x7b ? 0x7d : 0x5d)) {
          i++;
          state = 'after';
        } else if (c === 0x7b) {
          stack.push(new Set());
          state = 'key';
        } else {
          stack.push(null);
        }
        continue;
      }
      if (c === 0x22) {
        if (str() === null) return false;
      } else if (c === 0x74 || c === 0x66 || c === 0x6e) {
        const word = c === 0x74 ? 'true' : c === 0x66 ? 'false' : 'null';
        if (s.slice(i, i + word.length) !== word) return false;
        i += word.length;
      } else if (c === 0x30) {
        i++;
        if (isDigit(s.charCodeAt(i))) return false;
      } else if (c >= 0x31 && c <= 0x39) {
        while (isDigit(s.charCodeAt(i))) i++;
      } else {
        return false;
      }
      const next = s.charCodeAt(i);
      if (next === 0x2e || next === 0x65 || next === 0x45) return false;
      state = 'after';
    } else if (state === 'key') {
      if (s.charCodeAt(i) !== 0x22) return false;
      const key = str();
      const keys = stack.at(-1);
      if (key === null || !keys || keys.has(key)) return false;
      keys.add(key);
      ws();
      if (s.charCodeAt(i) !== 0x3a) return false;
      i++;
      state = 'value';
    } else {
      if (stack.length === 0) return i === n;
      const top = stack.at(-1);
      const c = s.charCodeAt(i);
      if (c === 0x2c) {
        i++;
        state = top ? 'key' : 'value';
      } else if ((c === 0x7d && top) || (c === 0x5d && top === null)) {
        i++;
        stack.pop();
      } else {
        return false;
      }
    }
  }
}

/** The capability paths the edge issues (section 13, Asset capabilities). */
const ASSET_PATH = /^\/v1\/puzzle\/asset\/[A-Za-z0-9_.-]{1,500}$/;
const KEY64 = /^[A-Za-z0-9_-]{1,64}$/;
const isInt = (v: unknown, lo: number, hi: number): v is number =>
  typeof v === 'number' && Number.isInteger(v) && v >= lo && v <= hi;

/** The puzzle of a native `puzzle` message as the page shows it (the frame's own check). */
export type BridgePuzzle = {
  kind: string;
  challenge: string;
  assets: string[];
  attemptsLeft: number;
  step?: number;
  steps?: number;
  options?: number;
  range?: { min: 0; max: number; step: 1 };
};

/**
 * The puzzle of a native message, read as the widget frame reads a solve's puzzle: unknown fields
 * are dropped (section 1; the rest of the message is exact-fields), an unknown `kind` is kept, and a
 * known kind must have its shape. A fresh object, or null.
 */
export function parseBridgePuzzle(value: unknown): BridgePuzzle | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const v = value as Record<string, unknown>;
  const { kind, challenge, assets, options, range, attemptsLeft, step, steps } = v;
  if (typeof kind !== 'string' || kind.length < 1 || kind.length > 40) return null;
  if (typeof challenge !== 'string' || challenge.length < 1 || challenge.length > 4096) return null;
  if (!Array.isArray(assets) || assets.length < 1 || assets.length > 9) return null;
  if (!assets.every((a) => typeof a === 'string' && ASSET_PATH.test(a))) return null;
  if (!isInt(attemptsLeft, 1, 3)) return null;
  const out: BridgePuzzle = { kind, challenge, assets: [...assets] as string[], attemptsLeft };
  if (step !== undefined || steps !== undefined) {
    if (!isInt(steps, 1, 9) || !isInt(step, 1, steps)) return null;
    out.step = step;
    out.steps = steps;
  }
  if (options !== undefined) {
    if (!isInt(options, 2, 9)) return null;
    out.options = options;
  }
  if (range !== undefined) {
    if (typeof range !== 'object' || range === null) return null;
    const r = range as Record<string, unknown>;
    if (r.min !== 0 || r.step !== 1 || (r.max !== 100 && r.max !== 359)) return null;
    out.range = { min: 0, max: r.max, step: 1 };
  }
  if (
    (kind === 'slider' && (out.range?.max !== 100 || assets.length < 2)) ||
    (kind === 'rotate' && out.range?.max !== 359) ||
    (kind === 'odd-one-out' && assets.length < 2) ||
    (kind === 'audio' && (out.options === undefined || out.options !== assets.length - 1))
  )
    return null;
  return out;
}

/** A native message as the page reads it (`parseNativeMessage`). */
export type ParsedNativeMessage =
  | {
      rg: 1;
      type: 'puzzle';
      id: string;
      puzzle: BridgePuzzle;
      signalsKey: string;
      cid: string;
      locale: string;
      theme: BridgeTheme;
    }
  | { rg: 1; type: 'mfa'; id: string; requestToken: string; languageCode?: string };

const NATIVE_FIELDS = Object.freeze({
  puzzle: ['rg', 'type', 'id', 'puzzle', 'signalsKey', 'cid', 'locale', 'theme'],
  mfa: ['rg', 'type', 'id', 'requestToken'],
});

/**
 * The reference reading of a native message by the hosted page, which the page's copy must match
 * (`mobile-bridge.json`, `nativeCases`), and which every message an SDK sends must pass. `raw` must
 * be message text (`BRIDGE_ENCODING`; anything but a string is null): at most `NATIVE_MAX_BYTES`
 * UTF-8 bytes, strict text (`isStrictBridgeText`), one object with exactly the fields of its type
 * (`languageCode` may be left out of `mfa`), `rg` 1, an id as for page messages, `signalsKey` and
 * `cid` base64url of 1 to 64 characters, `locale` and `languageCode` language codes of at most 35
 * characters, `theme` one of `BRIDGE_THEMES`, `requestToken` in the response-token charset, and the
 * puzzle as `parseBridgePuzzle` reads it. A fresh object, or null. Never throws.
 */
export function parseNativeMessage(raw: unknown): ParsedNativeMessage | null {
  try {
    if (typeof raw !== 'string') return null;
    if (raw.length > NATIVE_MAX_BYTES || utf8Length(raw) > NATIVE_MAX_BYTES) return null;
    if (!isStrictBridgeText(raw)) return null;
    const value: unknown = JSON.parse(raw);
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
    const v = value as Record<string, unknown>;
    const keys = Object.keys(v);
    const has = (list: readonly string[]) =>
      keys.length === list.length && keys.every((k) => list.includes(k));
    if (v.rg !== BRIDGE_VERSION) return null;
    const { id } = v;
    if (typeof id !== 'string' || !ID.test(id)) return null;
    if (v.type === 'puzzle') {
      if (!has(NATIVE_FIELDS.puzzle)) return null;
      const puzzle = parseBridgePuzzle(v.puzzle);
      const { signalsKey, cid, locale, theme } = v;
      if (puzzle === null || !isBridgeLocale(locale)) return null;
      if (typeof signalsKey !== 'string' || !KEY64.test(signalsKey)) return null;
      if (typeof cid !== 'string' || !KEY64.test(cid)) return null;
      if (!(BRIDGE_THEMES as readonly unknown[]).includes(theme)) return null;
      return {
        rg: 1,
        type: 'puzzle',
        id,
        puzzle,
        signalsKey,
        cid,
        locale,
        theme: theme as BridgeTheme,
      };
    }
    if (v.type === 'mfa') {
      const { requestToken, languageCode } = v;
      const fields =
        languageCode === undefined && !keys.includes('languageCode')
          ? NATIVE_FIELDS.mfa
          : [...NATIVE_FIELDS.mfa, 'languageCode'];
      if (!has(fields)) return null;
      if (typeof requestToken !== 'string' || !TOKEN.test(requestToken)) return null;
      if (languageCode !== undefined && !isBridgeLocale(languageCode)) return null;
      return {
        rg: 1,
        type: 'mfa',
        id,
        requestToken,
        ...(languageCode === undefined ? {} : { languageCode }),
      };
    }
    return null;
  } catch {
    return null;
  }
}

/** The page parameters as `appPageUrl` takes them and `parseAppPageQuery` returns them. */
export type AppPageParams = {
  siteKey: string;
  platform: 'android' | 'ios';
  appId: string;
  locale: string;
  theme: BridgeTheme;
};

/** Why `p` is not a well-formed set of page parameters, or null when it is. Never throws. */
function appPageParamsProblem(p: Record<string, unknown>): string | null {
  if (typeof p.siteKey !== 'string' || !isSiteKey(p.siteKey)) return 'siteKey is not a site key';
  if (p.platform !== 'android' && p.platform !== 'ios')
    return "platform must be 'android' or 'ios'";
  if (!isAppId(p.platform, p.appId)) return 'appId is not an app id';
  if (!isBridgeLocale(p.locale)) return 'locale is not a language code';
  if (!(BRIDGE_THEMES as readonly unknown[]).includes(p.theme))
    return 'theme must be light, dark or auto';
  return null;
}

/** A language code of at most 35 characters (`LANGUAGE_CODE`). */
const isBridgeLocale = (v: unknown): v is string =>
  typeof v === 'string' && v.length <= 35 && LOCALE.test(v);

/** The page's query parameters, in the order `appPageUrl` writes them. */
export const APP_PAGE_PARAMS = Object.freeze(['k', 'p', 'id', 'hl', 't'] as const);

/**
 * The reading of the hosted page's query (section 23.1), which the widget Worker applies: `search`
 * (with or without its `?`) must hold exactly `k, p, id, hl, t`, in that order, each once, with the
 * values `appPageUrl` accepts. Returns the parameters, or null for anything else. Never throws.
 */
export function parseAppPageQuery(search: string): AppPageParams | null {
  try {
    if (typeof search !== 'string') return null;
    const entries = [...new URLSearchParams(search)];
    if (entries.length !== APP_PAGE_PARAMS.length) return null;
    if (!entries.every(([key], i) => key === APP_PAGE_PARAMS[i])) return null;
    const [k, p, id, hl, t] = entries.map(([, v]) => v);
    const params = { siteKey: k, platform: p, appId: id, locale: hl, theme: t };
    return appPageParamsProblem(params) === null ? (params as AppPageParams) : null;
  } catch {
    return null;
  }
}

const LOOPBACK_HOSTS = Object.freeze(['localhost', '127.0.0.1', '[::1]', '10.0.2.2']);

/**
 * The URL of the hosted challenge page: `<origin>/v1/app?k=&p=&id=&hl=&t=`, in that parameter order,
 * each value percent-encoded. `widgetOrigin` must be a bare origin: `https:`, or `http:` only for
 * loopback and the Android emulator host (`10.0.2.2`), with no userinfo, path, query or fragment.
 * Throws TypeError for anything else, including a site key, app id, locale or theme that is not
 * well-formed.
 */
export function appPageUrl(
  widgetOrigin: string,
  p: {
    siteKey: string;
    platform: 'android' | 'ios';
    appId: string;
    locale: string;
    theme: BridgeTheme;
  },
): string {
  if (typeof widgetOrigin !== 'string') throw new TypeError('widgetOrigin must be a string');
  let u: URL;
  try {
    u = new URL(widgetOrigin);
  } catch {
    throw new TypeError('widgetOrigin is not a URL');
  }
  const bare =
    u.username === '' &&
    u.password === '' &&
    u.search === '' &&
    u.hash === '' &&
    u.pathname === '/' &&
    // `new URL` accepts `https://a.com/` and `https://a.com`; anything longer than the origin
    // (a path, a `?`, a `#`) is refused.
    (widgetOrigin === u.origin || widgetOrigin === `${u.origin}/`);
  if (!bare) throw new TypeError('widgetOrigin must be a bare origin');
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && LOOPBACK_HOSTS.includes(u.hostname)))
    throw new TypeError('widgetOrigin must be https (http only for loopback)');
  const problem = appPageParamsProblem(p);
  if (problem !== null) throw new TypeError(problem);
  const e = encodeURIComponent;
  return `${u.origin}/v1/app?k=${e(p.siteKey)}&p=${p.platform}&id=${e(p.appId)}&hl=${e(p.locale)}&t=${p.theme}`;
}

/** The SDK's own error codes (every SDK, every platform). */
export const MOBILE_OWN_ERROR_CODES = Object.freeze([
  'invalid-argument',
  'not-configured',
  'network-error',
  'timeout',
  'http-error',
  'invalid-response',
  'challenge-required',
  'challenge-unsupported',
  'cancelled',
  'busy',
  'internal',
] as const);

/**
 * Every code a mobile SDK reports: its own codes plus every API error code, passed through
 * unchanged. Append-only. A code outside this list is `internal`.
 */
export const MOBILE_SDK_ERRORS = Object.freeze([
  ...MOBILE_OWN_ERROR_CODES,
  ...API_ERROR_CODES.filter((c) => !(MOBILE_OWN_ERROR_CODES as readonly string[]).includes(c)),
] as const);
export type MobileSdkError = (typeof MOBILE_SDK_ERRORS)[number];

/** What an SDK does with one HTTP response of `/v1/challenge` or `/v1/solve`. */
/**
 * `reattest: true` when a solve's token or puzzle carries `attestation: "reattest"` (section 10): the
 * SDK discards its App Attest key and attests a new one on its next solve. Absent otherwise (`ok`,
 * no status, or a value the SDK does not know).
 */
export type ApiOutcome =
  | { kind: 'challenge' }
  | { kind: 'token'; token: string; expiresAt: number; reattest?: true }
  | { kind: 'puzzle'; reattest?: true }
  | { kind: 'error'; code: MobileSdkError; retryAfterSeconds?: number };

const RETRY_AFTER = /^[0-9]{1,9}$/;

function retryAfter(headers: Record<string, string>): number | undefined {
  for (const [name, value] of Object.entries(headers)) {
    if (name.toLowerCase() !== 'retry-after') continue;
    if (typeof value !== 'string' || !RETRY_AFTER.test(value)) return undefined;
    return Math.min(Number(value), MOBILE_RETRY_AFTER_MAX_SECONDS);
  }
  return undefined;
}

type Strict = { ok: true; value: Record<string, unknown> } | { ok: false };

/** Strict reading of a response body: UTF-8 (a byte-order mark is kept, so it fails), JSON object, no duplicate key. */
function strictObject(body: Uint8Array): Strict {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(body);
  } catch {
    return { ok: false };
  }
  if (hasDuplicateKeys(text, 'json')) return { ok: false };
  try {
    const v: unknown = JSON.parse(text);
    if (typeof v !== 'object' || v === null || Array.isArray(v)) return { ok: false };
    return { ok: true, value: v as Record<string, unknown> };
  } catch {
    return { ok: false };
  }
}

/**
 * The reference reading of an HTTP response from `/v1/challenge` (`op: 'challenge'`) or `/v1/solve`
 * (`op: 'solve'`), which the SDK ports must match (`mobile-client.json`, group `responses`):
 *
 * 1. A 3xx status is `http-error`; redirects are never followed and the body is not read.
 * 2. A body over `MOBILE_RESPONSE_MAX_BYTES` (64 KiB) is `invalid-response`, whatever the status.
 * 3. A status other than 200 is the API error code of an error body (`{ error: { code } }`, strict
 *    reading, a code in `API_ERROR_CODES`), passed through; any other body is `http-error`. On 429 and
 *    503 a `Retry-After` of whole seconds is reported as `retryAfterSeconds`, clamped to 3600.
 * 4. A 200 that is not strict (invalid UTF-8, a byte-order mark, malformed JSON, a duplicate key, a
 *    top-level value other than an object) or does not match the schema of the operation, an
 *    unknown solve `type` included, is `invalid-response`.
 * 5. A token or puzzle whose `attestation` is `reattest` is reported with `reattest: true`.
 */
export function interpretApiResponse(input: {
  op: 'challenge' | 'solve';
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}): ApiOutcome {
  const { op, status, headers, body } = input;
  const err = (code: MobileSdkError): ApiOutcome => {
    const out: ApiOutcome = { kind: 'error', code };
    if (status === 429 || status === 503) {
      const r = retryAfter(headers);
      if (r !== undefined) out.retryAfterSeconds = r;
    }
    return out;
  };
  if (status >= 300 && status < 400) return err('http-error');
  if (body.length > MOBILE_RESPONSE_MAX_BYTES) return err('invalid-response');
  const parsed = strictObject(body);
  if (status !== 200) {
    if (parsed.ok) {
      const e = parsed.value.error;
      if (typeof e === 'object' && e !== null && !Array.isArray(e)) {
        const code = (e as Record<string, unknown>).code;
        if (typeof code === 'string' && (API_ERROR_CODES as readonly string[]).includes(code))
          return err(code as MobileSdkError);
      }
    }
    return err('http-error');
  }
  if (!parsed.ok) return err('invalid-response');
  if (op === 'challenge') {
    return ChallengeResponse.safeParse(parsed.value).success
      ? { kind: 'challenge' }
      : err('invalid-response');
  }
  const r: z.ZodSafeParseResult<SolveResponse> = SolveResponseSchema.safeParse(parsed.value);
  if (!r.success) return err('invalid-response');
  const reattest = r.data.attestation === 'reattest' ? ({ reattest: true } as const) : {};
  if (r.data.type === 'puzzle') return { kind: 'puzzle', ...reattest };
  return { kind: 'token', token: r.data.token, expiresAt: r.data.expiresAt, ...reattest };
}
