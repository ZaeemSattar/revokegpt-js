import { toBase64Url } from './base64url.js';
import { ANDROID_PACKAGE, copyRegex, IOS_BUNDLE_ID } from './patterns.js';

/**
 * Native-app attestation (protocol v1 sections 4 and 10, M3; DeviceCheck M10): the app platforms, their app id
 * formats, the client's "attestation unavailable" codes and the binding bytes `B` that tie a Play
 * Integrity verdict or an App Attest attestation or assertion to one challenge, one site, one
 * action, one proof-of-work answer and one app.
 */

/** The app platforms of an app challenge. */
export const APP_PLATFORMS = Object.freeze(['android', 'ios'] as const);
export type AppPlatform = (typeof APP_PLATFORMS)[number];

/** The longest Android package name accepted (characters). */
export const ANDROID_PACKAGE_MAX_LENGTH = 255;
/** The longest iOS bundle id accepted (characters). */
export const IOS_BUNDLE_ID_MAX_LENGTH = 155;

// Public copies: the validators use private instances (src/patterns.ts), so mutating these exports
// cannot change what is accepted. The whole string must match; no trailing newline.
export const ANDROID_PACKAGE_RE: RegExp = copyRegex(ANDROID_PACKAGE);
export const IOS_BUNDLE_ID_RE: RegExp = copyRegex(IOS_BUNDLE_ID);

/**
 * True when `id` is a well-formed app id for `platform`: an Android package name of at most 255
 * characters matching `ANDROID_PACKAGE_RE`, or an iOS bundle id of at most 155 characters matching
 * `IOS_BUNDLE_ID_RE`. Anything else, an unknown platform included, is false. Never throws.
 */
export function isAppId(platform: unknown, id: unknown): boolean {
  if (typeof id !== 'string') return false;
  if (platform === 'android')
    return id.length <= ANDROID_PACKAGE_MAX_LENGTH && ANDROID_PACKAGE.test(id);
  if (platform === 'ios') return id.length <= IOS_BUNDLE_ID_MAX_LENGTH && IOS_BUNDLE_ID.test(id);
  return false;
}

/**
 * Why a client sends no attestation evidence (`{ kind: 'unavailable', code }`). Scored as
 * unavailable, never better than unattested traffic. Android `APP_NOT_INSTALLED` (-5) and
 * `APP_UID_MISMATCH` (-7) are deliberately absent: Google treats them as possible attacks, so the
 * client sends no `attestation` at all for them, and an app solve without one scores as failed.
 */
export const ATTEST_UNAVAILABLE_CODES = Object.freeze([
  'unsupported',
  'simulator',
  'os-too-old',
  'server-unavailable',
  'play-api-not-available',
  'play-store-not-found',
  'play-services-not-found',
  'play-services-outdated',
  'play-store-outdated',
  'cannot-bind',
  'network-error',
  'too-many-requests',
  'google-unavailable',
  'transient',
  'internal',
] as const);
export type AttestUnavailableCode = (typeof ATTEST_UNAVAILABLE_CODES)[number];

/**
 * Known values of the token response's `attestation`: `ok` (the evidence was accepted, or the
 * client's App Attest key is known) or `reattest` (the App Attest key is unknown: the client makes
 * a new key and attests it on its next solve). Clients must tolerate new values.
 */
export const ATTESTATION_STATUSES = Object.freeze(['ok', 'reattest'] as const);

/** The largest decoded App Attest attestation object and Play Integrity token (bytes, characters). */
export const ATTEST_LIMITS = Object.freeze({
  /** Decoded bytes of an App Attest attestation object. */
  attestationObjectBytes: 8192,
  /** Decoded bytes of an App Attest assertion. */
  assertionBytes: 2048,
  /** Characters of a Play Integrity token. */
  playTokenLength: 8192,
  /** Bytes of an App Attest key id (SHA-256 of the public key). */
  keyIdBytes: 32,
  /** Decoded bytes of a DeviceCheck device token (the cap, with room to spare). */
  deviceCheckTokenBytes: 4096,
} as const);

/** Versioned domain-separation prefix of the binding bytes. */
export const ATTEST_BINDING_DOMAIN = 'rg-attest-v1';

const encoder = new TextEncoder();
const DOMAIN_BYTES = encoder.encode(ATTEST_BINDING_DOMAIN);
const CID_BYTES = 16;
const MAX_FIELD_BYTES = 255;
const PLATFORM_BYTE: Readonly<Record<AppPlatform, number>> = Object.freeze({ android: 1, ios: 2 });

/** The bytes of an ASCII string. TypeError for a non-string or a non-ASCII character. */
function asciiBytes(s: unknown, what: string): Uint8Array {
  if (typeof s !== 'string') throw new TypeError(`${what} must be a string`);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0x7f) throw new TypeError(`${what} must be ASCII`);
    out[i] = c;
  }
  return out;
}

/**
 * The UTF-8 bytes of a string. TypeError for a non-string or a lone surrogate, which `TextEncoder`
 * would silently replace with U+FFFD (so two different strings would bind the same bytes).
 */
function utf8Bytes(s: unknown, what: string): Uint8Array {
  if (typeof s !== 'string') throw new TypeError(`${what} must be a string`);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError(`${what} has a lone surrogate`);
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) throw new TypeError(`${what} has a lone surrogate`);
  }
  return encoder.encode(s);
}

function checkFieldLength(b: Uint8Array, what: string): void {
  if (b.length > MAX_FIELD_BYTES) throw new RangeError(`${what} must be at most 255 bytes`);
}

/**
 * The attestation binding bytes `B` (protocol v1 section 10, App attestation binding), the same on
 * both platforms:
 *
 *   ASCII "rg-attest-v1" || cid (16) || u8 len || siteId (ASCII) || u8 len || action (ASCII)
 *   || SHA-256(solutions as consecutive 8-byte big-endian unsigned integers)
 *   || u8 platform (1 android, 2 ios) || u8 len || appId (UTF-8)
 *
 * `action` is the empty string when the challenge has none. The server rebuilds `B` from the
 * sealed challenge, the solve body and the site configuration; it never reads it from the client.
 *
 * Throws RangeError for a `cid` other than 16 bytes, a `siteId`, `action` or `appId` over 255
 * bytes, or a solution that is not an integer in [0, 2^53); TypeError for a `cid` that is not a
 * Uint8Array, a non-ASCII `siteId` or `action`, an `appId` with a lone surrogate, a non-array
 * `solutions` or an unknown platform. Everything is copied and checked before the first await, so
 * changing the caller's arrays afterwards changes nothing. Uses WebCrypto, so it is asynchronous.
 */
export async function buildAttestBinding(input: {
  cid: Uint8Array;
  siteId: string;
  action: string;
  solutions: readonly number[];
  platform: AppPlatform;
  appId: string;
}): Promise<Uint8Array> {
  const { cid: rawCid, siteId, action, solutions, platform, appId } = input;
  if (!(rawCid instanceof Uint8Array)) throw new TypeError('cid must be a Uint8Array');
  // Copied by its internal length, so a subclass lying through `length` changes nothing.
  const cid = new Uint8Array(rawCid);
  if (cid.byteLength !== CID_BYTES) throw new RangeError('cid must be exactly 16 bytes');
  const site = asciiBytes(siteId, 'siteId');
  checkFieldLength(site, 'siteId');
  const act = asciiBytes(action, 'action');
  checkFieldLength(act, 'action');
  const app = utf8Bytes(appId, 'appId');
  checkFieldLength(app, 'appId');
  let platformByte: number;
  if (platform === 'android') platformByte = PLATFORM_BYTE.android;
  else if (platform === 'ios') platformByte = PLATFORM_BYTE.ios;
  else throw new TypeError("platform must be 'android' or 'ios'");
  if (!Array.isArray(solutions)) throw new TypeError('solutions must be an array');
  const count = solutions.length;
  const nonces = new Uint8Array(8 * count);
  const view = new DataView(nonces.buffer);
  for (let i = 0; i < count; i++) {
    const n: unknown = solutions[i];
    if (typeof n !== 'number' || !Number.isInteger(n) || n < 0 || n > Number.MAX_SAFE_INTEGER)
      throw new RangeError('each solution must be an integer in [0, 2^53)');
    view.setUint32(8 * i, Math.floor(n / 2 ** 32));
    view.setUint32(8 * i + 4, n % 2 ** 32);
  }

  const solutionsHash = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', nonces));
  const out = new Uint8Array(
    DOMAIN_BYTES.length + CID_BYTES + 1 + site.length + 1 + act.length + 32 + 1 + 1 + app.length,
  );
  let o = 0;
  const put = (b: Uint8Array) => {
    out.set(b, o);
    o += b.length;
  };
  const putByte = (v: number) => {
    out[o++] = v;
  };
  put(DOMAIN_BYTES);
  put(cid);
  putByte(site.length);
  put(site);
  putByte(act.length);
  put(act);
  put(solutionsHash);
  putByte(platformByte);
  putByte(app.length);
  put(app);
  return out;
}

/** SHA-256 of a copy of `b`. TypeError unless `b` is a Uint8Array. */
async function sha256(b: Uint8Array): Promise<Uint8Array> {
  if (!(b instanceof Uint8Array)) throw new TypeError('binding must be a Uint8Array');
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new Uint8Array(b)));
}

/**
 * The Play Integrity `requestHash` for binding bytes `b`: base64url(SHA-256(b)), unpadded, 43
 * characters.
 */
export async function attestRequestHash(b: Uint8Array): Promise<string> {
  return toBase64Url(await sha256(b));
}

/** The App Attest `clientDataHash` for binding bytes `b`: SHA-256(b), 32 bytes. */
export async function attestClientDataHash(b: Uint8Array): Promise<Uint8Array> {
  return sha256(b);
}
