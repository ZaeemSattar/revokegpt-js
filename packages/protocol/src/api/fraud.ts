import { z } from 'zod';
import { containsPanRun } from '../fraud.js';
import { copyRegex, DATE_TIME, E164 } from '../patterns.js';

/** Payment fraud and SMS toll fraud (protocol v1 sections 20 and 21): the wire shapes of M8. */

/** The fixed values of `event.fraudPrevention`. */
export const FRAUD_PREVENTION_VALUES = Object.freeze([
  'FRAUD_PREVENTION_UNSPECIFIED',
  'ENABLED',
  'DISABLED',
] as const);

/**
 * Google's `TransactionEvent.TransactionEventType`, whole (REST reference
 * `projects.assessments/annotate`, accessed 2026-11-14).
 */
export const TRANSACTION_EVENT_TYPES = Object.freeze([
  'TRANSACTION_EVENT_TYPE_UNSPECIFIED',
  'MERCHANT_APPROVE',
  'MERCHANT_DENY',
  'MANUAL_REVIEW',
  'AUTHORIZATION',
  'AUTHORIZATION_DECLINE',
  'PAYMENT_CAPTURE',
  'PAYMENT_CAPTURE_DECLINE',
  'CANCEL',
  'CHARGEBACK_INQUIRY',
  'CHARGEBACK_ALERT',
  'FRAUD_NOTIFICATION',
  'CHARGEBACK',
  'CHARGEBACK_REPRESENTMENT',
  'CHARGEBACK_REVERSE',
  'REFUND_REQUEST',
  'REFUND_DECLINE',
  'REFUND',
  'REFUND_REVERSE',
] as const);

const Money = z.number().min(0).max(1e12);

export const Address = z.strictObject({
  recipient: z.string().max(100).optional(),
  address: z.array(z.string().max(100)).max(4).optional(),
  locality: z.string().max(100).optional(),
  administrativeArea: z.string().max(100).optional(),
  regionCode: z
    .string()
    .regex(/^[A-Z]{2}$/)
    .optional(),
  postalCode: z.string().max(16).optional(),
});

export const TransactionUser = z.strictObject({
  accountId: z.string().max(256).optional(),
  // At most 13 digits (epoch ms through the year 2286): the PAN scan skips this field, so a 14 to
  // 19 digit card number must not fit.
  creationMs: z
    .string()
    .regex(/^[0-9]{1,13}$/)
    .optional(),
  email: z.string().max(320).optional(),
  emailVerified: z.boolean().optional(),
  phoneNumber: z.string().max(32).optional(),
  phoneVerified: z.boolean().optional(),
});

export const TransactionItem = z.strictObject({
  name: z.string().max(100).optional(),
  value: Money.optional(),
  quantity: z.number().int().min(0).max(1_000_000).optional(),
  merchantAccountId: z.string().max(128).optional(),
});

export const GatewayInfo = z.strictObject({
  name: z
    .string()
    .regex(/^[a-z0-9_-]{1,32}$/)
    .optional(),
  gatewayResponseCode: z.string().max(64).optional(),
  avsResponseCode: z.string().max(8).optional(),
  cvvResponseCode: z.string().max(8).optional(),
});

function hasPanRun(v: unknown): boolean {
  if (typeof v === 'string') return containsPanRun(v);
  if (Array.isArray(v)) return v.some(hasPanRun);
  if (v !== null && typeof v === 'object') return Object.values(v).some(hasPanRun);
  return false;
}

/**
 * The card-number scan of a `user` or `merchants[]` entry. Two fields are exempt because their own
 * format already says what they hold: `creationMs` is at most 13 digits (epoch milliseconds, 13
 * digits today and Luhn-valid one time in ten), and a `phoneNumber` in E.164 is a phone number. A
 * `phoneNumber` that is not E.164 is scanned like any other string.
 */
function userHasPanRun(u: unknown): boolean {
  if (u === null || typeof u !== 'object' || Array.isArray(u)) return hasPanRun(u);
  return Object.entries(u).some(([k, v]) => {
    if (k === 'creationMs') return false;
    if (k === 'phoneNumber' && typeof v === 'string' && E164.test(v)) return false;
    return hasPanRun(v);
  });
}

function transactionHasPanRun(d: Record<string, unknown>): boolean {
  return Object.entries(d).some(([k, v]) =>
    k === 'user'
      ? userHasPanRun(v)
      : k === 'merchants' && Array.isArray(v)
        ? v.some(userHasPanRun)
        : hasPanRun(v),
  );
}

/**
 * The payment details of an assessment. Only the BIN (6 or 8 digits) and the last four digits of a
 * card are accepted; any other key is rejected, and so is any string anywhere in it that holds a
 * Luhn-valid 13 to 19 digit run (a card number), except a user's `creationMs` and E.164 `phoneNumber`. Never send an expiry, a CVV or track data.
 */
export const TransactionData = z
  .strictObject({
    transactionId: z.string().max(128).optional(),
    paymentMethod: z
      .string()
      .regex(
        /^(credit-card|debit-card|gift-card|processor-[a-z0-9-]{1,32}|custom-[a-z0-9-]{1,32})$/,
      )
      .optional(),
    cardBin: z
      .string()
      .regex(/^([0-9]{6}|[0-9]{8})$/)
      .optional(),
    cardLastFour: z
      .string()
      .regex(/^[0-9]{4}$/)
      .optional(),
    currencyCode: z
      .string()
      .regex(/^[A-Z]{3}$/)
      .optional(),
    value: Money.optional(),
    shippingValue: Money.optional(),
    shippingAddress: Address.optional(),
    billingAddress: Address.optional(),
    user: TransactionUser.optional(),
    merchants: z.array(TransactionUser).max(5).optional(),
    items: z.array(TransactionItem).max(20).optional(),
    gatewayInfo: GatewayInfo.optional(),
  })
  .refine((d) => !transactionHasPanRun(d), { message: 'a card number must never be sent' });
export type TransactionData = z.infer<typeof TransactionData>;

/** The open reason enums: any upper-case name is accepted; the closed lists are documented. */
const OpenReason = z.string().regex(/^[A-Z_]{1,64}$/);

const Risk = z.number().min(0).max(1);

export const FraudPreventionAssessment = z.looseObject({
  transactionRisk: Risk,
  riskReasons: z.array(z.looseObject({ reason: OpenReason })),
  cardTestingVerdict: z.looseObject({ risk: Risk }),
  stolenInstrumentVerdict: z.looseObject({ risk: Risk }),
  cardTestingRisk: Risk,
  stolenInstrumentRisk: Risk,
  unscored: z.literal(true).optional(),
});
export type FraudPreventionAssessment = z.infer<typeof FraudPreventionAssessment>;

export const PhoneFraudAssessment = z.looseObject({
  smsTollFraudVerdict: z.looseObject({
    risk: Risk,
    reasons: z.array(OpenReason),
    unscored: z.literal(true).optional(),
  }),
});
export type PhoneFraudAssessment = z.infer<typeof PhoneFraudAssessment>;

/** `:annotate` `transactionEvent`: the outcome of a payment the assessment scored. */
export const TransactionEvent = z.strictObject({
  eventType: z.enum(TRANSACTION_EVENT_TYPES),
  reason: z.string().max(64).optional(),
  value: Money.optional(),
  eventTime: z.string().regex(copyRegex(DATE_TIME)).optional(),
});
export type TransactionEvent = z.infer<typeof TransactionEvent>;
