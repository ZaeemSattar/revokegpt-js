import { fromBase64Url, toBase64Url } from './base64url.js';
import { timingSafeEqual } from './timing.js';

/** Assessment id (protocol v1 section 14). Stateless and self-authenticating. */

/** An id older than this (seconds, 30 days) answers `expired`. */
export const AID_MAX_AGE_SEC = 2_592_000;
export const AID_VERSION = 0x01;
/** Domain-separation label: the HKDF label for `k_aid` and the MAC input prefix. */
export const AID_DOMAIN = 'rg-aid-v1';
/** Encoded length: 31 bytes, 42 base64url characters. */
export const AID_LENGTH = 42;
const BODY_BYTES = 22; // tid(16) + iat(4) + score(1) + mode(1); the MAC input adds the version byte
const MAC_BYTES = 8;

/** Mode byte of an id. */
export const AID_MODES = Object.freeze({
  invisible: 0,
  checkbox: 1,
  score: 2,
  express: 3,
} as const);

export interface AidFields {
  tid: Uint8Array;
  iat: number;
  scoreTenths: number;
  mode: number;
}

export type AidDecoded = ({ ok: true } & AidFields) | { ok: false; why: 'not-found' | 'expired' };

const enc = new TextEncoder();

async function mac(k: CryptoKey, siteId: string, body: Uint8Array): Promise<Uint8Array> {
  const domain = enc.encode(AID_DOMAIN);
  const site = enc.encode(siteId);
  const input = new Uint8Array(domain.length + site.length + body.length);
  input.set(domain, 0);
  input.set(site, domain.length);
  input.set(body, domain.length + site.length);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, input)).subarray(0, MAC_BYTES);
}

/** Encodes an assessment id. Throws RangeError on out-of-range fields. */
export async function encodeAid(k: CryptoKey, siteId: string, f: AidFields): Promise<string> {
  if (!(f.tid instanceof Uint8Array) || f.tid.length !== 16)
    throw new RangeError('tid must be 16 bytes');
  if (!Number.isInteger(f.iat) || f.iat < 0 || f.iat > 0xffffffff)
    throw new RangeError('iat must be a u32');
  if (!Number.isInteger(f.scoreTenths) || f.scoreTenths < 0 || f.scoreTenths > 10)
    throw new RangeError('scoreTenths must be 0..10');
  if (!Number.isInteger(f.mode) || f.mode < 0 || f.mode > 255)
    throw new RangeError('mode must be a u8');
  // Layout: 0 version | 1..16 tid | 17..20 iat | 21 score | 22 mode | 23..30 mac.
  // The MAC covers bytes 0..22 (all 23 bytes before it, version included; the version is also checked).
  const out = new Uint8Array(BODY_BYTES + 1 + MAC_BYTES);
  out[0] = AID_VERSION;
  out.set(f.tid, 1);
  new DataView(out.buffer).setUint32(17, f.iat, false);
  out[21] = f.scoreTenths;
  out[22] = f.mode;
  out.set(await mac(k, siteId, out.subarray(0, 23)), 23);
  return toBase64Url(out);
}

/** Decodes and authenticates an id for `siteId`. Every failure but age is one `not-found`. */
export async function decodeAid(
  k: CryptoKey,
  siteId: string,
  aid: string,
  nowSec: number,
): Promise<AidDecoded> {
  const bad = { ok: false, why: 'not-found' } as const;
  if (typeof aid !== 'string' || aid.length !== AID_LENGTH) return bad;
  let b: Uint8Array;
  try {
    b = fromBase64Url(aid);
  } catch {
    return bad;
  }
  // Always compute the MAC, so a bad version costs the same as a bad MAC.
  const expected = await mac(k, siteId, b.subarray(0, 23));
  const macOk = timingSafeEqual(expected, b.subarray(23, 31));
  if (b.length !== 31 || b[0] !== AID_VERSION || !macOk) return bad;
  const iat = new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(17, false);
  if (nowSec - iat > AID_MAX_AGE_SEC) return { ok: false, why: 'expired' };
  return {
    ok: true,
    tid: b.slice(1, 17),
    iat,
    scoreTenths: b[21] as number,
    mode: b[22] as number,
  };
}
