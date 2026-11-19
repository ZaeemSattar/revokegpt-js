import { canonicalMailbox } from './account.js';
import { toBase64Url } from './base64url.js';
import { E164 } from './patterns.js';

/**
 * Payment fraud and SMS toll-fraud primitives (protocol v1 sections 20 and 21): the keyed hashes
 * that stand in for a card, a BIN, an email and a phone number, so no raw value is stored, logged
 * or put in a name, and the scan that keeps a card number out of a request.
 */

/** HKDF info prefixes: `<prefix><siteId>`, the domain separation between the five keys. */
export const FRAUD_KEY_INFO = Object.freeze({
  card: 'rg-card-v1|',
  bin: 'rg-bin-v1|',
  email: 'rg-email-v1|',
  phone: 'rg-phone-v1|',
  block: 'rg-pfx-v1|',
} as const);

/** Payment risk reasons in the order a response lists them. An open enum: clients MUST tolerate unknown values. */
export const FRAUD_RISK_REASONS = Object.freeze([
  'HIGH_TRANSACTION_VELOCITY',
  'EXCESSIVE_ENUMERATION_PATTERN',
  'SHORT_IDENTITY_HISTORY',
  'GEOLOCATION_DISCREPANCY',
  'ASSOCIATED_WITH_FRAUD_CLUSTER',
  'SUSPECTED_CARDING',
  'SUSPECTED_CHARGEBACK',
] as const);
export type FraudRiskReason = (typeof FRAUD_RISK_REASONS)[number];

/** SMS toll-fraud reasons. An open enum: clients MUST tolerate unknown values. */
export const SMS_TOLL_REASONS = Object.freeze([
  'INVALID_PHONE_NUMBER',
  'HIGH_COST_DESTINATION',
  'PREFIX_VELOCITY',
  'COUNTRY_MISMATCH',
  'VOIP_NUMBER',
  'NON_MOBILE_NUMBER',
  'LOW_CONVERSION',
] as const);
export type SmsTollReason = (typeof SMS_TOLL_REASONS)[number];

/** Every fraud hash keeps this many bytes of the HMAC (22 base64url characters). */
export const FRAUD_HASH_BYTES = 16;

const enc = new TextEncoder();
const BIN6 = /^\d{6}$/;
const LAST4 = /^\d{4}$/;
const CARD_BIN = /^(\d{6}|\d{8})$/;

/** The first 6 digits of a 6- or 8-digit BIN. Digits 7 and 8 are dropped before any hashing. */
export function bin6Of(cardBin: string): string {
  if (typeof cardBin !== 'string' || !CARD_BIN.test(cardBin))
    throw new TypeError('cardBin must be 6 or 8 digits');
  return cardBin.slice(0, 6);
}

async function mac(k: CryptoKey, input: string): Promise<string> {
  const out = new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(input)));
  return toBase64Url(out.subarray(0, FRAUD_HASH_BYTES));
}

/** The card fingerprint (key from `rg-card-v1|<siteId>`): `HMAC(K, bin6 ":" last4)`, 22 characters. */
export async function cardFp(k: CryptoKey, bin6: string, last4: string): Promise<string> {
  if (typeof bin6 !== 'string' || !BIN6.test(bin6)) throw new TypeError('bin6 must be 6 digits');
  if (typeof last4 !== 'string' || !LAST4.test(last4))
    throw new TypeError('last4 must be 4 digits');
  return mac(k, `${bin6}:${last4}`);
}

/** The BIN key (key from `rg-bin-v1|<siteId>`): `HMAC(K, bin6)`, 22 characters. */
export async function binKey(k: CryptoKey, bin6: string): Promise<string> {
  if (typeof bin6 !== 'string' || !BIN6.test(bin6)) throw new TypeError('bin6 must be 6 digits');
  return mac(k, bin6);
}

/** The email key (key from `rg-email-v1|<siteId>`): `HMAC(K, canonicalMailbox(email))`, 22 characters. */
export async function emailKey(k: CryptoKey, email: string): Promise<string> {
  if (typeof email !== 'string' || email.length === 0 || email.length > 320)
    throw new RangeError('email must be 1 to 320 characters');
  return mac(k, canonicalMailbox(email));
}

/** The phone key (key from `rg-phone-v1|<siteId>`): `HMAC(K, E.164)`, 22 characters. */
export async function phoneKey(k: CryptoKey, e164: string): Promise<string> {
  if (typeof e164 !== 'string' || !E164.test(e164)) throw new TypeError('e164 must be E.164');
  return mac(k, e164);
}

/**
 * The two number-block keys (key from `rg-pfx-v1|<siteId>`): `b2` hashes `"b2:"` and the E.164
 * number minus its last 2 digits (a 100-block), `b4` hashes `"b4:"` and the number minus its last 4
 * (a 10 000-block).
 */
export async function blockKeys(k: CryptoKey, e164: string): Promise<{ b2: string; b4: string }> {
  if (typeof e164 !== 'string' || !E164.test(e164)) throw new TypeError('e164 must be E.164');
  const [b2, b4] = await Promise.all([
    mac(k, `b2:${e164.slice(0, -2)}`),
    mac(k, `b4:${e164.slice(0, -4)}`),
  ]);
  return { b2, b4 };
}

function luhn(digits: string): boolean {
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

// A maximal run of digits with at most one space or dash between two digits. A double separator
// ends a run.
const DIGIT_RUN = /[0-9](?:[ -]?[0-9])*/g;

/**
 * True when `s` holds a likely card number. Each run of digits with at most one space or dash
 * between two digits is split on those separators into groups; the result is true when any
 * contiguous sequence of whole groups has 13 to 19 digits in total and passes the Luhn check, so a
 * card number next to a CVV, a year or a date is still found. A single unseparated run of 20 or
 * more digits is not flagged (an order id).
 */
export function containsPanRun(s: string): boolean {
  if (typeof s !== 'string') return false;
  for (const m of s.matchAll(DIGIT_RUN)) {
    const groups = m[0].split(/[ -]/);
    for (let i = 0; i < groups.length; i++) {
      let digits = '';
      for (let j = i; j < groups.length; j++) {
        digits += groups[j];
        if (digits.length > 19) break;
        if (digits.length >= 13 && luhn(digits)) return true;
      }
    }
  }
  return false;
}
