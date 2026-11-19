export const SITEVERIFY_ERROR_CODES = Object.freeze([
  'missing-input-secret',
  'invalid-input-secret',
  'missing-input-response',
  'invalid-input-response',
  'bad-request',
  'timeout-or-duplicate',
  'sitekey-secret-mismatch',
  'site-disabled',
  'quota-exceeded',
  'internal-error',
  // Paid plans: appended (append-only). `plan-required` = inactive plan, `plan-restricted` = restricted plan.
  'plan-required',
  'plan-restricted',
] as const);
export type SiteverifyErrorCode = (typeof SITEVERIFY_ERROR_CODES)[number];

/** Append-only: a code is never removed or reordered (clients must tolerate new codes). */
export const API_ERROR_CODES = Object.freeze([
  'bad-request',
  'not-found',
  'payload-too-large',
  'invalid-site-key',
  'hostname-not-allowed',
  'site-disabled',
  'challenge-expired',
  'challenge-invalid',
  'pow-invalid',
  'rate-limited',
  'quota-exceeded',
  'internal-error',
  'unsupported-media-type',
  // M3: an app challenge for an app the site does not list (the analogue of hostname-not-allowed).
  'app-not-allowed',
  // Paid plans: HTTP 402 (docs/protocol/v1.md section 19).
  'plan-required',
  'plan-restricted',
] as const);
export type ApiErrorCode = (typeof API_ERROR_CODES)[number];
