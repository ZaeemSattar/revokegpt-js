import { z } from 'zod';
import { PUZZLE_TELEMETRY_MAX_LENGTH } from '../constants.js';
import { ChallengeResponse } from './challenge.js';
import { OpaqueChallenge } from './common.js';
import { PuzzleResponse, TokenResponse } from './solve.js';

/**
 * `POST /v1/puzzle/answer` request (protocol v1 section 13). The answer is checked against the
 * value sealed in the challenge; `telemetry` is a scoring signal and never proof.
 */
export const PuzzleAnswerRequest = z.strictObject({
  challenge: OpaqueChallenge,
  answer: z.int().min(0).max(359).meta({
    description:
      "The solver's answer: slider position 0 to 100, rotation in degrees 0 to 359, or the index of the chosen option.",
  }),
  telemetry: z
    .string()
    .max(PUZZLE_TELEMETRY_MAX_LENGTH)
    .meta({
      description:
        'Base64url of the interaction signals blob, sealed to the server with the same envelope as ' +
        'solve signals. A scoring input only; an empty string is scored as missing telemetry.',
    }),
});
export type PuzzleAnswerRequest = z.infer<typeof PuzzleAnswerRequest>;

export const RetryResponse = z.looseObject({
  type: z.literal('retry'),
  challenge: ChallengeResponse,
});

/**
 * The `SolveResponse` union plus `retry`, sent after the wrong answer that ends a group: a fresh
 * challenge at proof-of-work difficulty `PUZZLE_POW_BUMP` bits higher. An answer that leaves the
 * group going (a correct one below `PUZZLE_GROUP_CORRECT`, or a wrong one within
 * `PUZZLE_GROUP_MAX_WRONG`) is a `puzzle` response: the next puzzle of the group, with `step`.
 */
export const PuzzleAnswerResponse = z.discriminatedUnion('type', [
  TokenResponse,
  PuzzleResponse,
  RetryResponse,
]);
export type PuzzleAnswerResponse = z.infer<typeof PuzzleAnswerResponse>;
