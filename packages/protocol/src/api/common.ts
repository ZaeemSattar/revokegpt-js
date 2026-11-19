import { z } from 'zod';
import {
  ANDROID_PACKAGE_MAX_LENGTH,
  type AppPlatform,
  IOS_BUNDLE_ID_MAX_LENGTH,
} from '../attest.js';
import { CHALLENGE_MAX_LENGTH } from '../constants.js';
import { canonicalizeHostname, HOSTNAME_MAX_LENGTH } from '../hostname.js';
import {
  ANDROID_PACKAGE,
  BASE64URL,
  copyRegex,
  HOSTNAME_LABELS,
  IOS_BUNDLE_ID,
  SITE_KEY,
} from '../patterns.js';
import { POW_LIMITS, type PowParams } from '../pow.js';

export const SiteKey = z
  .string()
  .regex(copyRegex(SITE_KEY))
  .meta({ description: 'Public site key.' });

/**
 * A hostname that is already canonical: `canonicalizeHostname(h) === h`. The length bound and the
 * lookahead-free label pattern appear in the OpenAPI document (portable to RE2); the refinement
 * also rejects shapes the pattern alone allows, such as `2130706433` (an IPv4 address in integer
 * form, canonical `127.0.0.1`) and invalid punycode such as `xn--a.com`.
 */
export const Hostname = z
  .string()
  .min(1)
  .max(HOSTNAME_MAX_LENGTH)
  .regex(copyRegex(HOSTNAME_LABELS))
  .refine((h) => canonicalizeHostname(h) === h, { message: 'hostname is not canonical' })
  .meta({
    description:
      'Canonical hostname of the embedding page: equal to its own canonicalization (lowercase A-labels, no trailing dot, IPv4 in dotted-decimal form, valid punycode).',
  });
/**
 * An app (M3): an Android package name or an iOS bundle id, discriminated on `platform`. There is
 * no `web` platform: a web client sends `hostname` instead.
 */
export const AppRef = z
  .discriminatedUnion('platform', [
    z.strictObject({
      platform: z.literal('android'),
      id: z.string().min(1).max(ANDROID_PACKAGE_MAX_LENGTH).regex(copyRegex(ANDROID_PACKAGE)).meta({
        description:
          'Android package name: two or more dot-separated segments, each a letter followed by `A-Z a-z 0-9 _`; at most 255 characters.',
      }),
    }),
    z.strictObject({
      platform: z.literal('ios'),
      id: z.string().min(1).max(IOS_BUNDLE_ID_MAX_LENGTH).regex(copyRegex(IOS_BUNDLE_ID)).meta({
        description:
          'iOS bundle id: two or more dot-separated segments of `A-Z a-z 0-9 -`; at most 155 characters.',
      }),
    }),
  ])
  .meta({ description: 'The app: its platform and its package name or bundle id.' });
export type AppRef = z.infer<typeof AppRef>;

export const OpaqueChallenge = z
  .string()
  .min(1)
  .max(CHALLENGE_MAX_LENGTH)
  .meta({ description: 'Sealed, opaque challenge blob. Return it unchanged.' });
export const UnixSeconds = z.int().meta({ description: 'Unix timestamp in seconds.' });

/**
 * Proof-of-work parameters. They only travel server to client, so the schema is lenient (unknown
 * fields kept, per the response forward-compatibility rule); `verifyPow` re-validates params itself.
 */
export const PowParamsSchema = z.looseObject({
  algorithm: z.literal('sha256-v1'),
  salt: z.string().regex(copyRegex(BASE64URL)).length(22).meta({
    description: 'Base64url salt: 22 characters, 16 bytes decoded (the challenge id).',
  }),
  difficultyBits: z.int().min(POW_LIMITS.minBits).max(POW_LIMITS.maxBits),
  count: z.int().min(POW_LIMITS.minCount).max(POW_LIMITS.maxCount),
});

// Compile-time check: the schema's output stays assignable to the verifier's PowParams type.
type _PowParamsCompatible = z.infer<typeof PowParamsSchema> extends PowParams ? true : never;
const _powParamsCompatible: _PowParamsCompatible = true;
void _powParamsCompatible;

// Compile-time check: the schema's platforms are exactly APP_PLATFORMS.
type _AppPlatformsMatch = AppRef['platform'] extends AppPlatform
  ? AppPlatform extends AppRef['platform']
    ? true
    : never
  : never;
const _appPlatformsMatch: _AppPlatformsMatch = true;
void _appPlatformsMatch;
