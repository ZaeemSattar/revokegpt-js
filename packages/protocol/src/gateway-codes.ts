/**
 * Customer payment-gateway decline codes, normalised to a small class set (protocol v1 section 20).
 * This is the one table (M8, R section 2.3). It is data: a code the table does not list gives
 * `UNKNOWN`, never an error. Bump `GATEWAY_CODES_VERSION` whenever a row changes.
 *
 * Sources and access dates:
 * - Stripe-style decline codes: https://docs.stripe.com/declines/codes, accessed 2026-11-09.
 * - Adyen refusal reasons (numbers and texts): https://docs.adyen.com/development-resources/refusal-reasons/,
 *   accessed 2026-11-09. Only the reasons that page lists with a clear meaning are mapped.
 * - Braintree processor responses:
 *   https://developer.paypal.com/braintree/docs/reference/general/processor-responses/authorization-responses,
 *   accessed 2026-11-14. The page labels only approved, declined, soft and hard; the class of each
 *   code below is our reading of its text.
 *
 * Several codes are results the customer's own shoppers must not see (`fraudulent`,
 * `merchant_blacklist`); this table only classifies them, and nothing echoes the raw code.
 */

/** The normalised outcome classes. */
export const DECLINE_CLASSES = Object.freeze([
  'APPROVED',
  'DECLINED_GENERIC',
  'DECLINED_ENUMERATION',
  'DECLINED_FUNDS',
  'DECLINED_ISSUER_FRAUD',
  'AUTH_REQUIRED',
  'ERROR',
  'UNKNOWN',
] as const);
export type DeclineClass = (typeof DECLINE_CLASSES)[number];

export const GATEWAY_CODES_VERSION = 1;

/** The gateway ids `gatewayInfo.name` is normalised against. */
export const GATEWAY_NAMES = Object.freeze(['stripe', 'adyen', 'braintree'] as const);
export type GatewayName = (typeof GATEWAY_NAMES)[number];

const ENUM = 'DECLINED_ENUMERATION';
const FRAUD = 'DECLINED_ISSUER_FRAUD';
const FUNDS = 'DECLINED_FUNDS';
const GENERIC = 'DECLINED_GENERIC';

function table(
  rows: readonly (readonly [DeclineClass, readonly string[]])[],
): ReadonlyMap<string, DeclineClass> {
  const m = new Map<string, DeclineClass>();
  for (const [cls, codes] of rows) for (const c of codes) m.set(c, cls);
  return m;
}

const STRIPE_STYLE = table([
  [
    ENUM,
    [
      'incorrect_number',
      'invalid_number',
      'incorrect_cvc',
      'invalid_cvc',
      'incorrect_zip',
      'invalid_expiry_month',
      'invalid_expiry_year',
      'invalid_expiry_date',
    ],
  ],
  [
    FRAUD,
    [
      'stolen_card',
      'lost_card',
      'pickup_card',
      'restricted_card',
      'fraudulent',
      'merchant_blacklist',
      'security_violation',
    ],
  ],
  [FUNDS, ['insufficient_funds', 'card_velocity_exceeded', 'withdrawal_count_limit_exceeded']],
  [GENERIC, ['generic_decline', 'do_not_honor', 'call_issuer']],
  ['AUTH_REQUIRED', ['authentication_required']],
  ['ERROR', ['processing_error', 'issuer_not_available', 'try_again_later']],
]);

const ADYEN = table([
  [GENERIC, ['2', 'refused']],
  [FRAUD, ['5', 'blocked card', '14', 'acquirer fraud', '20', 'fraud', '22', 'fraud-cancelled']],
  [FRAUD, ['25', 'restricted card', '31', 'issuer suspected fraud']],
  [ENUM, ['8', 'invalid card number', '24', 'cvc declined']],
  [FUNDS, ['12', 'not enough balance']],
]);

const BRAINTREE = table([
  ['APPROVED', ['1000', '1001', '1002', '1003', '1004', '1005']],
  [ENUM, ['2005', '2006', '2008', '2009', '2010', '2059', '2060']],
  [FRAUD, ['2012', '2013', '2014', '2021', '2047', '2053', '2077']],
  [FUNDS, ['2001', '2002', '2003']],
  ['AUTH_REQUIRED', ['2099']],
  ['ERROR', ['2031', '2105', '2106', '3000']],
  [
    GENERIC,
    [
      '2000',
      '2004',
      '2011',
      '2015',
      '2016',
      '2038',
      '2041',
      '2043',
      '2044',
      '2046',
      '2057',
      '2107',
      '2108',
    ],
  ],
]);

const TABLES: ReadonlyMap<string, ReadonlyMap<string, DeclineClass>> = new Map([
  ['stripe', STRIPE_STYLE],
  ['adyen', ADYEN],
  ['braintree', BRAINTREE],
]);

/**
 * Maps a gateway decline code to a class. It never throws: any input it does not know gives
 * `UNKNOWN`. With no gateway named a snake_case code is looked up in the Stripe-style table. Braintree
 * codes 2109 to 2999 are "Processor Declined" and map to `DECLINED_GENERIC`.
 */
export function normalizeGatewayCode(gateway: string | undefined, code: string): DeclineClass {
  if (typeof code !== 'string') return 'UNKNOWN';
  if (gateway !== undefined && typeof gateway !== 'string') return 'UNKNOWN';
  const key = code.trim().toLowerCase();
  const t = TABLES.get(gateway === undefined ? 'stripe' : gateway.trim().toLowerCase());
  if (t === undefined) return 'UNKNOWN';
  const hit = t.get(key);
  if (hit !== undefined) return hit;
  if (t === BRAINTREE && /^[0-9]{4}$/.test(key)) {
    const n = Number(key);
    if (n >= 2109 && n <= 2999) return GENERIC;
  }
  return 'UNKNOWN';
}

/** True only for the letter `N` (an AVS or CVV mismatch); the other letters are gateway-specific. */
export function avsCvvMismatch(letter?: string): boolean {
  return letter === 'N';
}
