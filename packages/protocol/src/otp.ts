import { BASE64URL_16, copyRegex, OTP_CODE } from './patterns.js';
import { timingSafeEqual } from './timing.js';

/**
 * One-time codes for account verification (protocol v1 section 17). A code is six digits drawn by
 * rejection sampling, so every code is equally likely; the server stores only an HMAC of it.
 */

export const OTP_DIGITS = 6;
/** u32 values at or above this are skipped: it is the largest multiple of 10^6 below 2^32, so no code is likelier. */
export const OTP_REJECT_LIMIT = 4_294_000_000;
/** A code, exactly six ASCII digits (a public copy). */
export const OTP_CODE_RE: RegExp = copyRegex(OTP_CODE);
/** A session id: 16 random bytes, base64url, 22 characters (a public copy). */
export const MFA_ID_RE: RegExp = copyRegex(BASE64URL_16);
/** HKDF info of the OTP MAC key, derived from `MFA_KEK` (`deriveSiteKey(kek, OTP_KEY_INFO)`). */
export const OTP_KEY_INFO = 'rg-otp-v1';

const MAX_DRAWS = 64;
const enc = new TextEncoder();

/**
 * A code from a source of uniform u32 values. Values at or above `OTP_REJECT_LIMIT` are skipped;
 * the code is the value modulo 10^6, zero padded to six digits (a leading zero is kept). Throws
 * RangeError when `next` returns anything but a u32, and after 64 draws without an accepted one
 * (the chance with a real source is below 10^-500).
 */
export function otpFromRandom(next: () => number): string {
  for (let i = 0; i < MAX_DRAWS; i++) {
    const v = next();
    if (!Number.isInteger(v) || v < 0 || v > 0xffffffff)
      throw new RangeError('next() must return a u32');
    if (v >= OTP_REJECT_LIMIT) continue;
    return String(v % 1_000_000).padStart(OTP_DIGITS, '0');
  }
  throw new RangeError('random source rejected every draw');
}

/** A fresh code from `crypto.getRandomValues`. */
export function newOtp(): string {
  const buf = new Uint32Array(1);
  return otpFromRandom(() => {
    crypto.getRandomValues(buf);
    return buf[0] as number;
  });
}

/**
 * The stored value for a code: `HMAC-SHA-256(K_otp, ASCII mfaId || ASCII code)`, 32 bytes. The
 * session id is fixed length, so the concatenation is unambiguous. `k` is the key from
 * `deriveSiteKey(MFA_KEK, OTP_KEY_INFO)`.
 */
export async function otpMac(k: CryptoKey, mfaId: string, code: string): Promise<Uint8Array> {
  if (typeof mfaId !== 'string' || !MFA_ID_RE.test(mfaId)) throw new TypeError('invalid mfaId');
  if (typeof code !== 'string' || !OTP_CODE_RE.test(code)) throw new TypeError('invalid code');
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(mfaId + code)));
}

/** Whether `code` matches the stored value, in constant time. A malformed code is a plain false. */
export async function otpMatches(
  k: CryptoKey,
  mfaId: string,
  code: string,
  stored: Uint8Array,
): Promise<boolean> {
  if (typeof code !== 'string' || !OTP_CODE_RE.test(code)) return false;
  return timingSafeEqual(await otpMac(k, mfaId, code), stored);
}
