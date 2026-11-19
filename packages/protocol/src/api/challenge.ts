import { z } from 'zod';
import {
  ACTION,
  BASE64URL,
  CDATA,
  copyRegex,
  SDK_NAME,
  SDK_VERSION,
  SITE_ID,
} from '../patterns.js';
import {
  AppRef,
  Hostname,
  OpaqueChallenge,
  PowParamsSchema,
  SiteKey,
  UnixSeconds,
} from './common.js';

const action = z.string().regex(copyRegex(ACTION)).optional();
const cdata = z.string().regex(copyRegex(CDATA)).optional();
const sdk = z.strictObject({
  name: z
    .string()
    .min(1)
    .max(40)
    .regex(copyRegex(SDK_NAME))
    .meta({ description: 'SDK name: `a-z 0-9 @ / . _ -`, 1 to 40 characters.' }),
  version: z
    .string()
    .min(1)
    .max(40)
    .regex(copyRegex(SDK_VERSION))
    .meta({ description: 'SDK version: `0-9 A-Z a-z . + -`, 1 to 40 characters.' }),
});

/**
 * A web challenge request: the embedding page's canonical `hostname`. There is deliberately no
 * `mode` field: the server always uses the site's configured mode, so a client cannot request a
 * weaker one. Every string field has a closed charset (no whitespace, controls or bidi characters)
 * matched against the whole string.
 */
export const WebChallengeRequest = z.strictObject({
  sitekey: SiteKey,
  hostname: Hostname,
  action,
  cdata,
  sdk,
});
export type WebChallengeRequest = z.infer<typeof WebChallengeRequest>;

/**
 * A native-app challenge request (M3): the `app` (platform and package name or bundle id) instead
 * of a hostname. Strict like the web shape: no `hostname`, no `mode`, no unknown field.
 */
export const AppChallengeRequest = z.strictObject({
  sitekey: SiteKey,
  app: AppRef,
  action,
  cdata,
  sdk,
});
export type AppChallengeRequest = z.infer<typeof AppChallengeRequest>;

/**
 * `/v1/challenge` request body: exactly one of the web shape (`hostname`) and the app shape
 * (`app`). Both shapes are strict, so a body with both, or with neither, matches no shape.
 */
export const ChallengeRequest = z.union([WebChallengeRequest, AppChallengeRequest]);
export type ChallengeRequest = z.infer<typeof ChallengeRequest>;

export const ChallengeResponse = z.looseObject({
  challenge: OpaqueChallenge,
  pow: PowParamsSchema,
  signals: z.looseObject({
    version: z.string().min(1).max(40),
    key: z.string().regex(copyRegex(BASE64URL)).min(1).max(64),
  }),
  expiresAt: UnixSeconds,
  siteId: z
    .string()
    .regex(copyRegex(SITE_ID))
    .optional()
    .meta({
      description:
        'App challenges only (M3): the site id, a lowercase canonical UUID, which the client ' +
        'binds into the attestation binding bytes (protocol v1 section 10). Absent on a web ' +
        'challenge. The server rebuilds the binding from the sealed challenge and never reads it ' +
        'back from the client.',
    }),
  appId: z
    .string()
    .min(1)
    .max(255)
    .optional()
    .meta({
      description:
        'App challenges only (M10): the sealed app id, `<teamId>.<bundleId>` on iOS and the package ' +
        'name on Android (at most 255 characters). The iOS client uses it in the attestation ' +
        'binding bytes only when it equals its own bundle id or ends with `.` plus it, so no Team ' +
        'ID setting is needed. Absent on a web challenge. Clients must tolerate its absence.',
    }),
});
export type ChallengeResponse = z.infer<typeof ChallengeResponse>;
