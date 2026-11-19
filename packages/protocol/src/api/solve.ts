import { z } from 'zod';
import { ATTEST_LIMITS, ATTEST_UNAVAILABLE_CODES, ATTESTATION_STATUSES } from '../attest.js';
import {
  PUZZLE_GROUP_CORRECT_AUDIO,
  PUZZLE_MAX_ATTEMPTS,
  SIGNALS_MAX_LENGTH,
  TOKEN_MAX_LENGTH,
} from '../constants.js';
import {
  APP_ATTEST_KEY_ID,
  BASE64_PADDED,
  copyRegex,
  PLAY_INTEGRITY_TOKEN,
  RESPONSE_TOKEN,
} from '../patterns.js';
import { OpaqueChallenge, UnixSeconds } from './common.js';

/** The number of bytes canonical padded base64 text `s` decodes to. */
const base64DecodedLength = (s: string) =>
  (s.length / 4) * 3 - (s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0);

/**
 * Canonical padded standard base64 that decodes to 1 to `maxBytes` bytes. The character bound is
 * exact for the regex (`4 * ceil(maxBytes / 3)`); the refinement checks the decoded length.
 */
const base64Blob = (maxBytes: number, description: string) =>
  z
    .string()
    .min(4)
    .max(4 * Math.ceil(maxBytes / 3))
    .regex(copyRegex(BASE64_PADDED))
    .refine((s) => base64DecodedLength(s) <= maxBytes, {
      message: `decodes to more than ${maxBytes} bytes`,
    })
    .meta({
      description: `${description} The JSON Schema \`maxLength\` (${4 * Math.ceil(maxBytes / 3)}) is the padded-text bound and admits one byte past the cap when the text ends in padding; the decoded length is enforced and wins.`,
    });

const AppAttestKeyId = z.string().regex(copyRegex(APP_ATTEST_KEY_ID)).meta({
  description:
    'App Attest key id: canonical padded standard base64 of 32 bytes (44 characters), as DCAppAttestService returns it.',
});

/**
 * The attestation evidence of an app solve (M3), discriminated on `kind`: a Play Integrity token,
 * an App Attest attestation (first use of a key) or assertion (later uses), a DeviceCheck device
 * token (the iOS fallback, M10), or the reason the
 * client has none. Each is bound to the challenge by the binding bytes `B` (protocol v1 section
 * 10), which the server rebuilds; the client sends only the platform's evidence.
 */
export const Attestation = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('play-integrity'),
    token: z
      .string()
      .min(1)
      .max(ATTEST_LIMITS.playTokenLength)
      .regex(copyRegex(PLAY_INTEGRITY_TOKEN))
      .meta({
        description:
          'Play Integrity standard-request token: 1 to 8192 characters of `A-Z a-z 0-9 _ . = -`.',
      }),
  }),
  z.strictObject({
    kind: z.literal('app-attest-attestation'),
    keyId: AppAttestKeyId,
    object: base64Blob(
      ATTEST_LIMITS.attestationObjectBytes,
      'App Attest attestation object: canonical padded standard base64 of at most 8192 bytes.',
    ),
  }),
  z.strictObject({
    kind: z.literal('app-attest-assertion'),
    keyId: AppAttestKeyId,
    assertion: base64Blob(
      ATTEST_LIMITS.assertionBytes,
      'App Attest assertion: canonical padded standard base64 of at most 2048 bytes.',
    ),
  }),
  z.strictObject({
    kind: z.literal('devicecheck'),
    token: base64Blob(
      ATTEST_LIMITS.deviceCheckTokenBytes,
      'DeviceCheck device token (iOS fallback, M10): canonical padded standard base64 of 1 to 4096 bytes. Not bound to the challenge; scored below App Attest.',
    ),
  }),
  z.strictObject({
    kind: z.literal('unavailable'),
    code: z.enum(ATTEST_UNAVAILABLE_CODES),
  }),
]);
export type Attestation = z.infer<typeof Attestation>;

export const SolveRequest = z.strictObject({
  challenge: OpaqueChallenge,
  pow: z.strictObject({
    solutions: z.array(z.int().min(0).max(Number.MAX_SAFE_INTEGER)).min(1).max(256),
  }),
  signals: z
    .string()
    .max(SIGNALS_MAX_LENGTH)
    .meta({
      description:
        'The browser signals, encrypted for this challenge with the key from the challenge ' +
        "response's `signals` bootstrap; opaque to every client but the widget. The edge scores " +
        'them (protocol v1 section 6): an empty string (the widget could not collect or encode ' +
        'them) is scored as missing signals, and text that does not decrypt and validate (another ' +
        "challenge's key, an unsupported collector release, garbage) as invalid signals. Both are " +
        'scored, never refused: the solve still gets a token, carrying its lower score.',
    }),
  attestation: Attestation.optional().meta({
    description:
      'App solves only (M3): the attestation evidence for an app challenge, bound to it by the ' +
      'binding bytes of protocol v1 section 10. Absent on a web solve.',
  }),
});
export type SolveRequest = z.infer<typeof SolveRequest>;

export const PUZZLE_KINDS = Object.freeze(['slider', 'rotate', 'odd-one-out', 'audio'] as const);

/** The puzzle a `type: "puzzle"` response carries (protocol v1 section 13). */
export const PuzzleSpec = z.looseObject({
  kind: z
    .string()
    .min(1)
    .max(40)
    .meta({
      description: `Known values: ${PUZZLE_KINDS.join(', ')}. Clients must tolerate new values.`,
    }),
  challenge: OpaqueChallenge,
  assets: z.array(z.string().min(1).max(512)).min(1).max(9).meta({
    description:
      'Capability paths of the puzzle images or audio, relative to the API origin. Each is HMAC-signed and valid for PUZZLE_ASSET_TTL_SECONDS; fetch them without credentials.',
  }),
  options: z.int().min(2).max(9).optional().meta({
    description: 'Odd-one-out and audio: how many choices there are. The answer is a choice index.',
  }),
  range: z
    .looseObject({
      min: z.literal(0),
      max: z.union([z.literal(359), z.literal(100)]),
      step: z.literal(1),
    })
    .optional()
    .meta({ description: 'Slider (0 to 100) and rotate (0 to 359): the answer range.' }),
  attemptsLeft: z.int().min(1).max(PUZZLE_MAX_ATTEMPTS).meta({
    description: 'Answers this puzzle still accepts: always PUZZLE_MAX_ATTEMPTS (1).',
  }),
  step: z.int().min(1).max(PUZZLE_GROUP_CORRECT_AUDIO).optional().meta({
    description:
      'The position of this puzzle in its group, 1 to steps: the number of correct answers so far plus one. Shown as "puzzle 1 of 2".',
  }),
  steps: z.int().min(1).max(PUZZLE_GROUP_CORRECT_AUDIO).optional().meta({
    description:
      'How many correct answers pass the group: PUZZLE_GROUP_CORRECT, or PUZZLE_GROUP_CORRECT_AUDIO once the group is audio.',
  }),
});
export type PuzzleSpec = z.infer<typeof PuzzleSpec>;

/**
 * The App Attest status of an app solve (M3; on a puzzle too since M10): a string, not an enum, so
 * clients tolerate new values.
 */
const AttestationStatus = z
  .string()
  .min(1)
  .max(40)
  .optional()
  .meta({
    description: `App solves only, App Attest evidence only. Known values: ${ATTESTATION_STATUSES.join(', ')} (\`reattest\`: discard the App Attest key, make a new key and attest it on the next solve). Sent on the token, or on the puzzle when the solve escalates (M10). Clients must tolerate new values.`,
  });

export const TokenResponse = z.looseObject({
  type: z.literal('token'),
  // The same charset siteverify accepts as `response` (F5a follow-up 6).
  token: z.string().min(1).max(TOKEN_MAX_LENGTH).regex(copyRegex(RESPONSE_TOKEN)),
  expiresAt: UnixSeconds,
  // App solves only (M3).
  attestation: AttestationStatus,
});
export const PuzzleResponse = z.looseObject({
  type: z.literal('puzzle'),
  puzzle: PuzzleSpec,
  // App solves that escalate (M10): the status the token would have carried, so a client told to
  // re-attest learns it even when it never gets a token from this solve.
  attestation: AttestationStatus,
});

/**
 * Discriminated on `type`. A client that receives an unknown `type` (which does not parse) MUST
 * treat the solve as failed (not verified); it may retry or fall back.
 */
export const SolveResponse = z.discriminatedUnion('type', [TokenResponse, PuzzleResponse]);
export type SolveResponse = z.infer<typeof SolveResponse>;
