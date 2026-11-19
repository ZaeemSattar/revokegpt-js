import type { PolicyKey } from './schema.js';

/**
 * TEST-ONLY keys. Their private seeds are public, in `scripts/generate-policy-vectors.ts`
 * (SHA-256 of a labelled string), and they must never sign or verify anything real. They are
 * never part of PINNED_POLICY_KEYS; a test passes them explicitly.
 */
export const TEST_POLICY_KEYS: readonly PolicyKey[] = Object.freeze([
  {
    kid: '3d75ce3772a93b6e',
    alg: 'Ed25519',
    pub: 'mkgsn6TedEnh1On988cT8ujJnUMDF1SaeTPCjRaasF0',
    notAfter: 4_102_444_800,
  },
  {
    kid: '30c94a60406a6ea6',
    alg: 'Ed25519',
    pub: 'nvfcYJX2dOZjA0fjvFW_XkspaP7RVu5_Shw-muGLXj0',
    notAfter: 4_102_444_800,
  },
  {
    kid: '990ae9db448cb6fd',
    alg: 'Ed25519',
    pub: 'JMmCSFznt-U2yeFyfLpLykQcWQoyuZXv701HS8xeFxw',
    notAfter: 1_700_000_000,
  },
] as const);

/** TEST-ONLY session signing keys (same caveat as TEST_POLICY_KEYS). */
export const TEST_SESSION_KEYS: readonly PolicyKey[] = Object.freeze([
  {
    kid: '2328cee6ad3983b9',
    alg: 'Ed25519',
    pub: '_ZO-OOkW_HMTK-Ax_nEqKzerqsGbc_X7vXd_oWAzWmk',
    notAfter: 4_102_444_800,
  },
] as const);

/**
 * The production bundle keys, current and next (docs/runbooks/m9-firewall-operations.md section 2).
 * Only `current` signs; `next` is pinned ahead so a rotation needs no release.
 */
export const PRODUCTION_POLICY_KEYS: readonly PolicyKey[] = Object.freeze([
  {
    kid: 'dc43cba74b531a58',
    alg: 'Ed25519',
    pub: '9aawK32yAp7kIuAaLJYE7Y5W40w0TjJxuaoqSe2NNuA',
    notAfter: 4_102_444_800,
  },
  {
    kid: '79105aac0b45dd0c',
    alg: 'Ed25519',
    pub: 'ZdstW3eqBJ7TpwPkudQKVd_g2wNqUsGSMUKOzXpCF9M',
    notAfter: 4_102_444_800,
  },
] as const);

/** The production session signing keys, current and next. */
export const PRODUCTION_SESSION_KEYS: readonly PolicyKey[] = Object.freeze([
  {
    kid: 'cd7e0df68b55c9ce',
    alg: 'Ed25519',
    pub: 'WlDajxX_FgHup2I3O4qlujgfgBhZdwBIhs5dqqDrXwM',
    notAfter: 4_102_444_800,
  },
  {
    kid: 'e3386ef628ea8430',
    alg: 'Ed25519',
    pub: 'oDW6PsK0hRuxprSto16YCyuY_tcZcI4aH1TyhUfD6Ms',
    notAfter: 4_102_444_800,
  },
] as const);

/** The pinned bundle keys: production keys only. Tests opt in to TEST_POLICY_KEYS explicitly. */
export const PINNED_POLICY_KEYS: readonly PolicyKey[] = Object.freeze([...PRODUCTION_POLICY_KEYS]);

/** The pinned session keys: production keys only. Tests opt in to TEST_SESSION_KEYS explicitly. */
export const PINNED_SESSION_KEYS: readonly PolicyKey[] = Object.freeze([
  ...PRODUCTION_SESSION_KEYS,
]);
