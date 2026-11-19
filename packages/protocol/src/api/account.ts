import { z } from 'zod';
import { ACCOUNT_ID_MAX_BYTES, VERIFICATION_RESULTS } from '../account.js';
import { TOKEN_MAX_LENGTH } from '../constants.js';
import {
  copyRegex,
  DATE_TIME,
  E164,
  EMAIL_ADDRESS,
  HASHED_ACCOUNT_ID,
  LANGUAGE_CODE,
  OTP_CODE,
  RESPONSE_TOKEN,
} from '../patterns.js';

/** Account protection and account verification (protocol v1 sections 15 and 17): the wire shapes of M7. */

/** Body limits (bytes) of the M7 endpoints; `/v1/assessments` keeps its 8 KiB. */
export const ERASE_BODY_LIMIT = 1024;
export const MFA_BODY_LIMIT = 1024;
/** The wait before a resend, in seconds (also the value `resendAfter` carries after a send). */
export const MFA_RESEND_AFTER_SECONDS = 60;
/** A session lives this long, and so does a code. */
export const MFA_SESSION_TTL_SECONDS = 600;
/** Sends per session (the first included) and wrong codes per session, resends included. */
export const MFA_MAX_SENDS = 3;
export const MFA_MAX_ATTEMPTS = 5;
/** Sessions per endpoint hash per hour and per day. */
export const MFA_ENDPOINT_SESSIONS_PER_HOUR = 3;
export const MFA_ENDPOINT_SESSIONS_PER_DAY = 10;
/** A `createAccountTime` this many seconds old or less makes the assessment an account creation. */
export const ACCOUNT_CREATE_WINDOW_SECONDS = 600;

const utf8Length = (s: string) => new TextEncoder().encode(s).length;

export const AccountIdField = z
  .string()
  .min(1)
  .max(ACCOUNT_ID_MAX_BYTES)
  .refine((s) => utf8Length(s) <= ACCOUNT_ID_MAX_BYTES, { message: 'more than 256 UTF-8 bytes' })
  .meta({
    description:
      'Your account identifier: 1 to 256 UTF-8 bytes. Send this or `hashedAccountId`, never both.',
  });

export const HashedAccountIdField = z.string().regex(copyRegex(HASHED_ACCOUNT_ID)).meta({
  description:
    'A hash of your account identifier you computed: canonical padded standard base64 of exactly 32 bytes (44 characters). Send this or `accountId`, never both.',
});

const exactlyOneOf = (keys: string[]) => (o: Record<string, unknown>) =>
  keys.filter((k) => o[k] !== undefined).length === 1;

const UserId = z
  .strictObject({
    email: z.string().min(1).max(320).optional(),
    phoneNumber: z.string().min(1).max(32).optional(),
    username: z.string().min(1).max(256).optional(),
  })
  .refine(exactlyOneOf(['email', 'phoneNumber', 'username']), {
    message: 'exactly one of email, phoneNumber and username',
  });

/** `event.userInfo` (section 15). */
export const UserInfo = z
  .strictObject({
    accountId: AccountIdField.optional(),
    hashedAccountId: HashedAccountIdField.optional(),
    createAccountTime: z
      .string()
      .meta({ override: { pattern: DATE_TIME.source } })
      .refine((s) => DATE_TIME.test(s), { message: 'not an RFC 3339 date-time' })
      .optional()
      .meta({
        description:
          'When the account was created (RFC 3339). At most 600 seconds before now makes the assessment an account creation; otherwise it is a login.',
      }),
    userIds: z.array(UserId).max(10).optional().meta({
      description:
        "Accepted for compatibility. Ignored, except that with the site's `smsTollFraud` flag on the first `phoneNumber` is scored for SMS toll fraud (section 21): it is used only in request memory, stored only as keyed hashes and never logged. Nothing else here is stored, hashed or logged.",
    }),
  })
  .refine((o) => !(o.accountId !== undefined && o.hashedAccountId !== undefined), {
    message: 'send accountId or hashedAccountId, never both',
  });
export type UserInfo = z.infer<typeof UserInfo>;

const AccountVerificationEndpoint = z.union([
  z.strictObject({
    emailAddress: z.string().regex(copyRegex(EMAIL_ADDRESS)).max(254),
  }),
  z.strictObject({
    phoneNumber: z.string().regex(copyRegex(E164)).meta({
      description:
        'E.164. Accepted by the schema; answered `403 feature-disabled` until SMS is offered (section 17).',
    }),
  }),
]);

/** Top-level `accountVerification` of a request (section 17). The deprecated `username` is not accepted. */
export const AccountVerificationRequest = z.strictObject({
  endpoints: z.array(AccountVerificationEndpoint).min(1).max(2),
  languageCode: z.string().max(35).regex(copyRegex(LANGUAGE_CODE)).optional(),
});

const RequestToken = z.string().min(1).max(TOKEN_MAX_LENGTH).regex(copyRegex(RESPONSE_TOKEN));

/** `accountDefenderAssessment` of a response (section 15). */
export const AccountDefenderAssessment = z.looseObject({
  labels: z.array(z.string().max(64)).meta({
    description:
      'Labels from an open enum: `PROFILE_MATCH`, `SUSPICIOUS_LOGIN_ACTIVITY`, `SUSPICIOUS_ACCOUNT_CREATION`, `RELATED_ACCOUNTS_NUMBER_HIGH` and `CREDENTIAL_STUFFING_SUSPECTED`. Clients MUST tolerate unknown labels. A label never comes with the rule, count or threshold behind it.',
  }),
});

/** `accountVerification` of a response (section 17). */
export const AccountVerificationResponse = z.looseObject({
  endpoints: z.array(
    z.union([
      z.looseObject({ requestToken: RequestToken }),
      z.looseObject({
        lastVerificationTime: z.string().meta({ override: { pattern: DATE_TIME.source } }),
      }),
    ]),
  ),
  latestVerificationResult: z.enum(VERIFICATION_RESULTS),
});

// ----- /v1/mfa/send, /v1/mfa/verify -----

export const MfaSendRequest = z.strictObject({ requestToken: RequestToken });
export type MfaSendRequest = z.infer<typeof MfaSendRequest>;

export const MfaSendResponse = z.union([
  z.looseObject({
    sent: z.literal(true),
    resendAfter: z.number().int().min(0).max(MFA_SESSION_TTL_SECONDS).meta({
      description: 'Seconds before another send is accepted.',
    }),
  }),
  z.looseObject({
    result: z.enum(VERIFICATION_RESULTS).meta({
      description: 'The send did not happen; the session is over with this result.',
    }),
  }),
]);
export type MfaSendResponse = z.infer<typeof MfaSendResponse>;

export const MfaVerifyRequest = z.strictObject({
  requestToken: RequestToken,
  code: z.string().regex(copyRegex(OTP_CODE)),
});
export type MfaVerifyRequest = z.infer<typeof MfaVerifyRequest>;

export const MfaVerifyResponse = z.union([
  z.looseObject({
    token: z.string().regex(copyRegex(RESPONSE_TOKEN)).meta({
      description:
        'The final answer, whether the code was right or the attempts ran out. Present it as `event.token` in an assessment of the same account; it is single use.',
    }),
  }),
  z.looseObject({ retry: z.literal(true) }),
]);
export type MfaVerifyResponse = z.infer<typeof MfaVerifyResponse>;

// ----- /v1/accounts:erase -----

export const EraseRequest = z
  .strictObject({
    accountId: AccountIdField.optional(),
    hashedAccountId: HashedAccountIdField.optional(),
  })
  .refine(exactlyOneOf(['accountId', 'hashedAccountId']), {
    message: 'send exactly one of accountId and hashedAccountId',
  });
export type EraseRequest = z.infer<typeof EraseRequest>;

export const EraseResponse = z.looseObject({});
