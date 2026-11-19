import { z } from 'zod';
import { TOKEN_MAX_LENGTH } from '../constants.js';
import { canonicalizeIp } from '../ip.js';
import { ACTION, CDATA, copyRegex, DATE_TIME, RESPONSE_TOKEN } from '../patterns.js';
import { REASON_CODES } from '../reasons.js';
import {
  AccountDefenderAssessment,
  AccountIdField,
  AccountVerificationRequest,
  AccountVerificationResponse,
  HashedAccountIdField,
  UserInfo,
} from './account.js';
import { SiteKey } from './common.js';
import {
  FRAUD_PREVENTION_VALUES,
  FraudPreventionAssessment,
  PhoneFraudAssessment,
  TransactionData,
  TransactionEvent,
} from './fraud.js';

/** Assessments (protocol v1 section 14): the wire shapes of M6. */

/** Google's annotation `Reason` enum, whole (research 1.3). */
export const ANNOTATION_REASONS = Object.freeze([
  'CHARGEBACK',
  'CHARGEBACK_FRAUD',
  'CHARGEBACK_DISPUTE',
  'REFUND',
  'REFUND_FRAUD',
  'TRANSACTION_ACCEPTED',
  'TRANSACTION_DECLINED',
  'PAYMENT_HEURISTICS',
  'INITIATED_TWO_FACTOR',
  'PASSED_TWO_FACTOR',
  'FAILED_TWO_FACTOR',
  'CORRECT_PASSWORD',
  'INCORRECT_PASSWORD',
  'SOCIAL_SPAM',
] as const);

/**
 * What `:annotate` `reasons` accepts: Google's whole enum plus the `PAYMENT_FRAUD` alias that the
 * edge rewrites (protocol v1 section 20). The alias never reaches the annotation queue, whose schema
 * keeps `ANNOTATION_REASONS`.
 */
export const ANNOTATE_INPUT_REASONS = Object.freeze([
  ...ANNOTATION_REASONS,
  'PAYMENT_FRAUD',
] as const);

export const ASSESSMENT_INVALID_REASONS = Object.freeze([
  'MALFORMED',
  'EXPIRED',
  'DUPE',
  'MISSING',
  'UNEXPECTED_ACTION',
  'KEY_MISMATCH',
  'DOMAIN_MISMATCH',
] as const);

/** The only express scores; every express response also carries `LOW_CONFIDENCE_SCORE`. */
export const EXPRESS_SCORES = Object.freeze([0.1, 0.3, 0.5, 0.7] as const);

/** Error codes the assessment endpoints add; they are not siteverify or challenge codes. */
export const ASSESSMENT_ERROR_CODES = Object.freeze([
  'unauthorized',
  'expired',
  'service-unavailable',
  // M6 Task 5: the site has not enabled the endpoint (its `assessments`, `express` or `annotations` flag).
  'feature-disabled',
] as const);

/** Limits of the request bodies (bytes). */
export const ASSESSMENT_BODY_LIMIT = 8192;
export const ANNOTATE_BODY_LIMIT = 2048;

const UserIp = z
  .string()
  .max(45)
  .refine((v) => canonicalizeIp(v) !== null, { message: 'Invalid IP address' })
  .meta({ description: 'End-user IP address (IPv4 or IPv6). Express only.' });

export const AssessmentEvent = z.strictObject({
  token: z.string().min(1).max(TOKEN_MAX_LENGTH).regex(copyRegex(RESPONSE_TOKEN)).optional(),
  siteKey: SiteKey.optional(),
  expectedAction: z.string().regex(copyRegex(ACTION)).optional(),
  express: z.boolean().optional(),
  userIpAddress: UserIp.optional(),
  userAgent: z.string().max(1000).optional(),
  headers: z.array(z.string().max(1024)).max(50).optional(),
  ja4: z.string().max(64).optional(),
  requestedUri: z.string().max(2048).optional(),
  userInfo: UserInfo.optional(),
  // M8 (protocol v1 section 20).
  fraudPrevention: z.enum(FRAUD_PREVENTION_VALUES).optional(),
  transactionData: TransactionData.optional(),
});

export const AssessmentRequest = z.strictObject({
  event: AssessmentEvent,
  // M7 (protocol v1 sections 16 and 17).
  accountVerification: AccountVerificationRequest.optional(),
});
export type AssessmentRequest = z.infer<typeof AssessmentRequest>;

export const AssessmentResponse = z.looseObject({
  name: z
    .string()
    .regex(/^assessments\/[A-Za-z0-9_-]{42}$/)
    .meta({ description: '`assessments/<aid>`; the aid is 42 base64url characters.' }),
  riskAnalysis: z.looseObject({
    score: z.number().min(0).max(1),
    reasons: z.array(z.enum(REASON_CODES)),
    challenge: z.literal('PASSED').optional(),
  }),
  tokenProperties: z.looseObject({
    valid: z.boolean(),
    invalidReason: z.enum(ASSESSMENT_INVALID_REASONS).optional(),
    createTime: z.string().meta({ override: { pattern: DATE_TIME.source } }),
    hostname: z.string().optional(),
    androidPackageName: z.string().optional(),
    iosBundleId: z.string().optional(),
    action: z.string().optional(),
    cdata: z.string().regex(copyRegex(CDATA)).optional(),
  }),
  event: z.looseObject({
    expectedAction: z.string().optional(),
    express: z.boolean(),
  }),
  // M7 (protocol v1 sections 15 to 17); each is present only when it applies.
  accountDefenderAssessment: AccountDefenderAssessment.optional(),
  requiresMfa: z.boolean().optional(),
  accountVerification: AccountVerificationResponse.optional(),
  // M8 (protocol v1 sections 20 and 21); each is present only when it applies.
  fraudPreventionAssessment: FraudPreventionAssessment.optional(),
  phoneFraudAssessment: PhoneFraudAssessment.optional(),
});
export type AssessmentResponse = z.infer<typeof AssessmentResponse>;

export const AnnotateRequest = z
  .strictObject({
    annotation: z.enum(['LEGITIMATE', 'FRAUDULENT']).optional(),
    reasons: z.array(z.enum(ANNOTATE_INPUT_REASONS)).max(14).optional(),
    // M7 (protocol v1 section 15): the account a password or two-factor outcome belongs to.
    accountId: AccountIdField.optional(),
    hashedAccountId: HashedAccountIdField.optional(),
    // M8 (protocol v1 section 20): the outcome of a scored payment.
    transactionEvent: TransactionEvent.optional(),
  })
  .refine((o) => !(o.accountId !== undefined && o.hashedAccountId !== undefined), {
    message: 'send accountId or hashedAccountId, never both',
  });
export type AnnotateRequest = z.infer<typeof AnnotateRequest>;

export const AnnotateResponse = z.looseObject({});
