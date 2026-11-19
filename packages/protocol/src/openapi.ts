// Build-time only: not exported from src/index.ts and excluded from dist (tsconfig.build.json).
// The script (scripts/write-openapi.ts) and tests import this file directly.

import { z } from 'zod';
import { createDocument, type oas32 } from 'zod-openapi';
import {
  ERASE_BODY_LIMIT,
  EraseRequest,
  EraseResponse,
  MFA_BODY_LIMIT,
  MfaSendRequest,
  MfaSendResponse,
  MfaVerifyRequest,
  MfaVerifyResponse,
} from './api/account.js';
import {
  ANNOTATE_BODY_LIMIT,
  AnnotateRequest,
  AnnotateResponse,
  ASSESSMENT_BODY_LIMIT,
  AssessmentRequest,
  AssessmentResponse,
} from './api/assessments.js';
import { ChallengeRequest, ChallengeResponse } from './api/challenge.js';
import { SiteKey } from './api/common.js';
import { ApiError } from './api/errors.js';
import {
  PolicyBundle,
  RgKeys,
  SESSION_BODY_LIMIT,
  SessionRequest,
  SessionResponse,
} from './api/policy.js';
import { PuzzleAnswerRequest, PuzzleAnswerResponse } from './api/puzzle.js';
import {
  SiteverifyCompatRequest,
  SiteverifyRequest,
  SiteverifyResponse,
} from './api/siteverify.js';
import { SolveRequest, SolveResponse } from './api/solve.js';

const json = <T>(schema: T) => ({ 'application/json': { schema } });

const payloadTooLarge = {
  '413': { description: 'Request body too large.', content: json(ApiError) },
};
const internalError = {
  '500': { description: 'Internal error.', content: json(ApiError) },
};
// Paid plans (docs/protocol/v1.md section 19): the site's organization has no active plan.
const planRequired = {
  '402': {
    description:
      'The organization has no active plan (`plan-required`), or its plan is restricted for this endpoint (`plan-restricted`). Section 19.',
    content: json(ApiError),
  },
};
const clientErrorResponses = {
  '400': { description: 'Malformed or invalid request.', content: json(ApiError) },
  ...payloadTooLarge,
  '415': {
    description:
      'Unsupported media type (`unsupported-media-type`): a body whose media type is not application/json, or a non-identity `Content-Encoding`.',
    content: json(ApiError),
  },
  ...internalError,
};

const bearer = [{ secretKey: [] }];
const assessErrors = {
  '400': { description: 'Malformed or invalid request (`bad-request`).', content: json(ApiError) },
  '401': {
    description:
      'Missing, invalid or management secret, or a disabled site (`unauthorized`): one uniform answer.',
    content: json(ApiError),
  },
  '403': {
    description: 'The site has not enabled this endpoint (`feature-disabled`).',
    content: json(ApiError),
  },
  '413': { description: 'Request body too large.', content: json(ApiError) },
  '415': {
    description: 'Unsupported media type (`unsupported-media-type`).',
    content: json(ApiError),
  },
  '429': {
    description: 'Rate limited (`rate-limited`). Carries `Retry-After: 1`.',
    content: json(ApiError),
  },
  '500': { description: 'Internal error.', content: json(ApiError) },
  '503': {
    description:
      'Assessments are switched off or unavailable (`service-unavailable`). Siteverify is unaffected.',
    content: json(ApiError),
  },
};

// M7 widget-facing endpoints: no Bearer; the `requestToken` is the credential. Like /v1/solve they
// answer 415 for another media type and carry the widget CORS rules. A forged, malformed or expired
// `requestToken`, or an unknown or disabled site, is one 404; a well-formed token whose session is
// unknown or already over is not a 404 (send answers a `result`, verify `retry`).
const mfaErrors = {
  '400': { description: 'Malformed or invalid request (`bad-request`).', content: json(ApiError) },
  '403': {
    description: 'The site has not enabled account verification (`feature-disabled`).',
    content: json(ApiError),
  },
  '404': {
    description:
      'Forged, malformed or expired `requestToken`, or an unknown or disabled site (`not-found`): one answer in body and status.',
    content: json(ApiError),
  },
  '413': { description: 'Request body too large.', content: json(ApiError) },
  '415': {
    description: 'Unsupported media type (`unsupported-media-type`).',
    content: json(ApiError),
  },
  '429': {
    description: 'Rate limited (`rate-limited`). Carries `Retry-After: 1`.',
    content: json(ApiError),
  },
  '500': { description: 'Internal error.', content: json(ApiError) },
  '503': {
    description:
      'Account verification is switched off or unavailable (`service-unavailable`). Siteverify is unaffected.',
    content: json(ApiError),
  },
};

const SITEVERIFY_DESCRIPTION =
  'Verifies a response token. Server-to-server only. ' +
  'Every input, authentication or authorization failure (missing or invalid secret; missing, invalid, expired or duplicate response; ' +
  'sitekey mismatch; disabled site; quota; a browser request carrying an Origin header) is answered with HTTP 200 and ' +
  '`{ "success": false, "error-codes": [...] }`. A request carrying an Origin header gets `error-codes: ["bad-request"]` and no CORS headers. ' +
  'The only non-200 responses are 413 (body too large) and 5xx (internal error); clients MUST treat any non-200 as not verified. ' +
  'The secret is sent in the request body, or as `Authorization: Bearer`, never in the URL. ' +
  'A body in another media type, or with a non-identity `Content-Encoding`, is a malformed body: 200 with `bad-request`, never 415. ' +
  'Accepts application/x-www-form-urlencoded and application/json. (Server behaviour arrives in M1.)';

const siteverifyOperation = (
  operationId: string,
  summary: string,
  requestSchema: typeof SiteverifyRequest | typeof SiteverifyCompatRequest,
  extraDescription = '',
) => ({
  operationId,
  summary,
  description:
    SITEVERIFY_DESCRIPTION +
    ' Firewall integrations send the secret as `Authorization: Bearer rgsk_...` instead of the body field `secret`; the secret is in exactly one of the two (both is `bad-request`).' +
    extraDescription,
  // Optional Bearer: the secret is either the body field or the header (exactly one).
  security: [{}, ...bearer],
  requestBody: {
    required: true,
    content: {
      'application/x-www-form-urlencoded': { schema: requestSchema },
      'application/json': { schema: requestSchema },
    },
  },
  responses: {
    '200': {
      description:
        'Verification result. `success: false` with `error-codes` for every input, authentication or authorization failure.',
      content: json(SiteverifyResponse),
    },
    ...payloadTooLarge,
    ...internalError,
  },
});

export function buildOpenApiDocument(): oas32.OpenAPIObject {
  return createDocument({
    openapi: '3.1.0',
    info: {
      title: 'RevokeGPT API',
      version: '1.0.0-draft',
      license: { name: 'MIT', identifier: 'MIT' },
    },
    servers: [{ url: 'https://api.revokegpt.com', description: 'Placeholder server' }],
    components: {
      securitySchemes: {
        secretKey: {
          type: 'http',
          scheme: 'bearer',
          description: 'The site secret key (`rgsk_...`) as `Authorization: Bearer`.',
        },
      },
    },
    paths: {
      '/v1/challenge': {
        post: {
          operationId: 'createChallenge',
          summary: 'Request a challenge',
          description:
            'The server determines the mode from the site configuration; the request has no mode field.',
          security: [],
          requestBody: { required: true, content: json(ChallengeRequest) },
          responses: {
            ...planRequired,
            '200': { description: 'Challenge issued.', content: json(ChallengeResponse) },
            ...clientErrorResponses,
          },
        },
      },
      '/v1/solve': {
        post: {
          operationId: 'solveChallenge',
          summary: 'Submit a challenge solution',
          description:
            'A client that receives an unknown `type` MUST treat the solve as failed (not verified); it may retry or fall back.',
          security: [],
          requestBody: { required: true, content: json(SolveRequest) },
          responses: {
            '200': {
              description: 'A response token, or a puzzle to solve.',
              content: json(SolveResponse),
            },
            ...clientErrorResponses,
          },
        },
      },
      '/v1/puzzle/answer': {
        post: {
          operationId: 'answerPuzzle',
          summary: 'Answer a puzzle',
          description:
            'Checks the answer against the value sealed in the challenge. Each puzzle takes one answer (PUZZLE_MAX_ATTEMPTS) and its challenge string is then spent; the next response carries a fresh one. ' +
            'A person passes a group by answering PUZZLE_GROUP_CORRECT puzzles correctly (PUZZLE_GROUP_CORRECT_AUDIO in an audio group). A correct answer before that, or a wrong one within PUZZLE_GROUP_MAX_WRONG, returns the next puzzle of the group (`step` and `steps` count the progress); ' +
            'the answer that completes the group returns a token, and the wrong answer after PUZZLE_GROUP_MAX_WRONG wrong ones returns `retry` with a fresh challenge at PoW difficulty PUZZLE_POW_BUMP bits higher. ' +
            'A client that receives an unknown `type` MUST treat the answer as failed.',
          security: [],
          requestBody: { required: true, content: json(PuzzleAnswerRequest) },
          responses: {
            '200': {
              description: 'A token, the next puzzle of the group, or a fresh challenge.',
              content: json(PuzzleAnswerResponse),
            },
            ...clientErrorResponses,
          },
        },
      },
      '/v1/siteverify': {
        post: siteverifyOperation(
          'siteverify',
          'Verify a response token',
          SiteverifyRequest,
          ' Unknown request fields are rejected (`bad-request`).',
        ),
      },
      '/v1/assessments': {
        post: {
          operationId: 'createAssessment',
          summary: 'Create an assessment (token or express)',
          description:
            'Server-to-server. A token assessment verifies a response token (one use, shared with siteverify) and returns its score and reasons; an express assessment (`event.express: true`) scores `event.userIpAddress` with no token. ' +
            `Body limit ${ASSESSMENT_BODY_LIMIT / 1024} KiB. JSON only; a query string or an Origin header is \`bad-request\`. ` +
            '`event.userInfo` is accepted as before and ignored when the site has neither account protection nor MFA on, and under `ACCOUNT_KILL`. Account verification (`accountVerification`) is off until the site enables it (`403 feature-disabled`). ' +
            'Payment fraud (`event.transactionData`, section 20) and SMS toll fraud (a phone number in `event.userInfo`, section 21) are each off until the site enables them (`403 feature-disabled`); `event.fraudPrevention: DISABLED` skips payment scoring. A card number, expiry, CVV or track data in `transactionData` is `bad-request`. Every other field not listed is rejected. The shadow score, the model, the fired rules and the rule, count or threshold behind a label are never returned.',
          security: bearer,
          requestBody: { required: true, content: json(AssessmentRequest) },
          responses: {
            ...planRequired,
            '200': { description: 'The assessment.', content: json(AssessmentResponse) },
            ...assessErrors,
          },
        },
      },
      '/v1/assessments/{id}:annotate': {
        post: {
          operationId: 'annotateAssessment',
          summary: 'Annotate an assessment',
          description:
            'Labels an assessment of the authenticated site. A wrong site, a forged or altered id and a bad version are one `404 not-found`; an id older than 30 days is `410 expired`. ' +
            `Body limit ${ANNOTATE_BODY_LIMIT / 1024} KiB. \`PASSWORD_*\` annotations are \`bad-request\`. \`transactionEvent\` reports the outcome of a scored payment; the reason \`PAYMENT_FRAUD\` is an alias the edge rewrites (section 20).`,
          security: bearer,
          requestParams: {
            path: z.object({ id: z.string().regex(/^[A-Za-z0-9_-]{42}$/) }),
          },
          requestBody: { required: true, content: json(AnnotateRequest) },
          responses: {
            ...planRequired,
            '200': { description: 'Recorded. Empty object.', content: json(AnnotateResponse) },
            ...assessErrors,
            '404': { description: 'Unknown assessment (`not-found`).', content: json(ApiError) },
            '410': {
              description: 'Assessment older than 30 days (`expired`).',
              content: json(ApiError),
            },
          },
        },
      },
      '/v1/accounts:erase': {
        post: {
          operationId: 'eraseAccount',
          summary: 'Erase the stored profile of an account',
          description:
            'Server-to-server. Deletes the profile and the related-account entries kept for the account of the authenticated site (GDPR erasure). ' +
            'Answers 200 whether or not anything was stored. Needs a valid site secret only: no feature flag, and neither `ACCOUNT_KILL` nor `ASSESS_KILL` stops it. ' +
            `Body limit ${ERASE_BODY_LIMIT / 1024} KiB. Exactly one of \`accountId\` and \`hashedAccountId\`.`,
          security: bearer,
          requestBody: { required: true, content: json(EraseRequest) },
          responses: {
            '200': { description: 'Done. Empty object.', content: json(EraseResponse) },
            ...assessErrors,
          },
        },
      },
      '/v1/mfa/send': {
        post: {
          operationId: 'sendMfaCode',
          summary: 'Send the one-time code',
          description:
            'Widget-facing, with the CORS and Origin rules of `/v1/solve`. Authenticated by the `requestToken` of an assessment response only. ' +
            `Body limit ${MFA_BODY_LIMIT / 1024} KiB. Sends a six-digit code to the endpoint of the session: at most 3 sends per session, 60 seconds apart. ` +
            'A send that cannot happen answers 200 with a `result` instead of `sent`.',
          security: [],
          requestBody: { required: true, content: json(MfaSendRequest) },
          responses: {
            ...planRequired,
            '200': { description: 'Sent, or a final result.', content: json(MfaSendResponse) },
            ...mfaErrors,
          },
        },
      },
      '/v1/mfa/verify': {
        post: {
          operationId: 'verifyMfaCode',
          summary: 'Verify the one-time code',
          description:
            'Widget-facing, with the CORS and Origin rules of `/v1/solve`. Authenticated by the `requestToken` only. ' +
            `Body limit ${MFA_BODY_LIMIT / 1024} KiB. A session allows 5 wrong codes in total. A wrong code with attempts left answers \`retry\`; the right code, and the last wrong one, answer a final \`token\` (whose assessment says \`SUCCESS_USER_VERIFIED\` or \`ERROR_USER_NOT_VERIFIED\`), given once per session. A session that is unknown or already over also answers \`retry\`.`,
          security: [],
          requestBody: { required: true, content: json(MfaVerifyRequest) },
          responses: {
            ...planRequired,
            '200': { description: 'A final token, or retry.', content: json(MfaVerifyResponse) },
            ...mfaErrors,
          },
        },
      },
      '/v1/policies/{siteKey}': {
        get: {
          operationId: 'getPolicyBundle',
          summary: 'Fetch the signed firewall policy bundle of a site',
          description:
            'Public by site key, unless the owner marked the bundle private: then `Authorization: Bearer rgsk_...` (the site secret) is required and a missing or wrong one is `401 unauthorized`. Returns the bundle of section 18.5 as JSON with an `ETag`; a request with a matching `If-None-Match` gets 304. ' +
            'Cached for 60 seconds at the edge. The bundle is signed (Ed25519): integrations verify it against pinned keys and never trust the transport. ' +
            'An unknown or disabled site, and a site that has published no policy, are one `404 not-found`. Integrations that hold a secret send it on every fetch (section 18.5).',
          security: [{}, ...bearer],
          requestParams: { path: z.object({ siteKey: SiteKey }) },
          responses: {
            ...planRequired,
            '200': {
              description: 'The signed bundle.',
              headers: {
                ETag: {
                  description: 'Entity tag of the served bundle.',
                  schema: { type: 'string' },
                },
              },
              content: json(PolicyBundle),
            },
            '304': { description: 'Not modified.' },
            '401': {
              description:
                'A private bundle fetched without the matching site secret as Bearer (`unauthorized`).',
              content: json(ApiError),
            },
            '404': {
              description: 'Unknown site or no published policy (`not-found`).',
              content: json(ApiError),
            },
            '429': {
              description: 'Rate limited (`rate-limited`). Carries `Retry-After: 1`.',
              content: json(ApiError),
            },
            ...internalError,
          },
        },
      },
      '/.well-known/rg-keys.json': {
        get: {
          operationId: 'getRgKeys',
          summary: 'Public signing keys',
          description:
            'The public halves of the bundle and session signing keys, with `kid` and `notAfter`, for monitoring and rotation. Integrations pin their keys (`PINNED_POLICY_KEYS`); this file never replaces the pins. (Server behaviour arrives in M9 Task 5.)',
          security: [],
          responses: {
            '200': { description: 'The keys.', content: json(RgKeys) },
            ...internalError,
          },
        },
      },
      '/v1/session': {
        post: {
          operationId: 'createSession',
          summary: 'Exchange a response token for a session or clearance token',
          description:
            'Widget-facing, with the CORS and Origin rules of `/v1/solve` (the widget frame calls it). Spends the response token (one use) and returns an offline-verifiable token (section 18.6) that the page hands to the integration once, in the `X-RG-Session-Init` header (session) or the `rg_clearance` field of the `/__rg/return` form (clearance). The optional `X-RG-Session-Prev` header carries the previous session so its hard maximum age is kept. ' +
            `Body limit ${SESSION_BODY_LIMIT / 1024} KiB. 20 requests per second per site.`,
          security: [],
          requestBody: { required: true, content: json(SessionRequest) },
          responses: {
            ...planRequired,
            '200': { description: 'The token.', content: json(SessionResponse) },
            '400': {
              description:
                'Malformed request, unknown or disabled site (`bad-request`, `invalid-site-key`, `site-disabled`), a hostname the site does not allow (`hostname-not-allowed`), or a response token that is invalid (`MALFORMED`), expired (`EXPIRED`), already spent (`DUPE`) or of the wrong action (`UNEXPECTED_ACTION`).',
              content: json(ApiError),
            },
            '403': {
              description: "A refresh past the first token's hard maximum age (`session-expired`).",
              content: json(ApiError),
            },
            ...payloadTooLarge,
            '415': {
              description: 'Unsupported media type (`unsupported-media-type`).',
              content: json(ApiError),
            },
            '429': {
              description: 'Rate limited (`rate-limited`). Carries `Retry-After: 1`.',
              content: json(ApiError),
            },
            ...internalError,
          },
        },
      },
      '/recaptcha/api/siteverify': {
        post: siteverifyOperation(
          'siteverifyCompat',
          'Verify a response token (drop-in compatible path)',
          SiteverifyCompatRequest,
          ' Unknown request fields (for example `version` from existing server libraries) are ignored.',
        ),
      },
    },
  });
}
