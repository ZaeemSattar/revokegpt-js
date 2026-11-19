import { z } from 'zod';
import { TOKEN_MAX_LENGTH } from '../constants.js';
import { copyRegex, RESPONSE_TOKEN } from '../patterns.js';
import { POLICY_ALGS, POLICY_LIMITS } from '../policy/limits.js';
import { SiteKey } from './common.js';

// Firewall policy endpoints (protocol v1, section 18). The bundle payload and the session claims
// are base64url JSON inside these strings; their schemas are PolicyBundlePayloadSchema (the
// reference implementation) and the claims of section 18.6.

const B64U_CHARS = /^[A-Za-z0-9_-]+$/;

/** The served, signed policy bundle. `payload` is the exact signed bytes, base64url without padding. */
export const PolicyBundle = z
  .looseObject({
    alg: z.enum(POLICY_ALGS).meta({ description: 'Signature algorithm. Ed25519 only.' }),
    kid: z
      .string()
      .regex(/^[0-9a-f]{16}$/)
      .meta({
        description: 'First 8 bytes of SHA-256(raw public key), 16 lower-case hex characters.',
      }),
    payload: z
      .string()
      .min(1)
      .max(Math.ceil((POLICY_LIMITS.maxBundleBytes * 4) / 3))
      .regex(copyRegex(B64U_CHARS))
      .meta({
        description:
          'The signed payload bytes (UTF-8 JSON, at most 64 KiB), base64url without padding. Verify the exact bytes; never re-serialise.',
      }),
    sig: z
      .string()
      .regex(/^[A-Za-z0-9_-]{86}$/)
      .meta({
        description:
          'Ed25519 signature (64 bytes, S below the group order) over utf8("rg-policy-v1") + 0x00 + payload bytes, base64url.',
      }),
  })
  .meta({ id: 'PolicyBundle', description: 'A signed firewall policy bundle (section 18.5).' });
export type PolicyBundle = z.infer<typeof PolicyBundle>;

const PublicKey = z.looseObject({
  kid: z.string().regex(/^[0-9a-f]{16}$/),
  alg: z.enum(POLICY_ALGS),
  pub: z
    .string()
    .regex(/^[A-Za-z0-9_-]{43}$/)
    .meta({ description: 'Raw 32-byte public key, base64url.' }),
  notAfter: z.int().meta({ description: 'Unix seconds; the key is not accepted after this time.' }),
});

/** Public keys behind the pinned set, for monitoring and rotation. Integrations pin keys; they do not trust this file. */
export const RgKeys = z.looseObject({
  policy: z.array(PublicKey).meta({ description: 'Bundle signing keys (current and next).' }),
  session: z.array(PublicKey).meta({ description: 'Session token signing keys.' }),
});
export type RgKeys = z.infer<typeof RgKeys>;

/** A session or clearance token: `v1.<kid>.<payload>.<sig>`. */
export const SessionToken = z
  .string()
  .max(POLICY_LIMITS.maxSessionTokenLength)
  .regex(/^v1\.[0-9a-f]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{86}$/)
  .meta({
    id: 'SessionToken',
    description:
      'Offline-verifiable token (section 18.6): `v1.<kid>.<payload b64url>.<sig b64url>`, signed over utf8("rg-session-v1") + 0x00 + payload bytes with a key distinct from the bundle key. The payload holds `sid host iat exp max lvl sc jti` and nothing that identifies a person.',
  });
export type SessionToken = z.infer<typeof SessionToken>;

export const SESSION_BODY_LIMIT = 1024;

export const SessionRequest = z.strictObject({
  sitekey: SiteKey,
  token: z.string().min(1).max(TOKEN_MAX_LENGTH).regex(copyRegex(RESPONSE_TOKEN)).meta({
    description:
      'A response token from `/v1/solve`: action `rg_session` for `kind` session, `rg_challenge` for `kind` clearance. It is spent here (one use).',
  }),
  kind: z.enum(['session', 'clearance']).meta({
    description:
      'Which token to issue: `session` (level 0, the cookie `__Host-rg_s`) or `clearance` (level 1, or 2 after a solved puzzle; the cookie `__Host-rg_c`).',
  }),
});
export type SessionRequest = z.infer<typeof SessionRequest>;

export const SessionResponse = z.looseObject({
  session: SessionToken,
  exp: z.int().meta({ description: 'Unix seconds; the token `exp`.' }),
});
export type SessionResponse = z.infer<typeof SessionResponse>;
