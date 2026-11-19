import { fromBase64Url, toBase64Url } from '../base64url.js';
import { POLICY_ALGS, POLICY_LIMITS, POLICY_SIGNATURE_DOMAIN } from './limits.js';
import { type PolicyBundlePayload, PolicyBundlePayloadSchema, type PolicyKey } from './schema.js';
import { keyIsConsistent, signDomain, verifyDomain } from './sig.js';

export type BundleFailure =
  | 'sig'
  | 'kid'
  | 'expired'
  | 'not-yet'
  | 'rollback'
  | 'size'
  | 'schema'
  | 'site';
export type BundleResult =
  | { ok: true; payload: PolicyBundlePayload; bytes: Uint8Array }
  | { ok: false; reason: BundleFailure };

const fail = (reason: BundleFailure): BundleResult => ({ ok: false, reason });
const encoder = new TextEncoder();

/**
 * Serialise and sign a bundle payload. The signed bytes are the UTF-8 of `JSON.stringify(payload)`
 * as written; verifiers never re-serialise. The served form is
 * `{"alg":"Ed25519","kid":...,"payload":<b64url>,"sig":<b64url>}`.
 */
export async function signBundle(payload: unknown, key: CryptoKey, kid: string): Promise<string> {
  const bytes = encoder.encode(JSON.stringify(payload));
  const sig = await signDomain(key, POLICY_SIGNATURE_DOMAIN, bytes);
  return JSON.stringify({
    alg: POLICY_ALGS[0],
    kid,
    payload: toBase64Url(bytes),
    sig: toBase64Url(sig),
  });
}

/** Sign raw payload bytes (the vector generator uses this to build bundles with exact bytes). */
export async function signBundleBytes(
  bytes: Uint8Array,
  key: CryptoKey,
  kid: string,
): Promise<string> {
  const sig = await signDomain(key, POLICY_SIGNATURE_DOMAIN, bytes);
  return JSON.stringify({
    alg: POLICY_ALGS[0],
    kid,
    payload: toBase64Url(bytes),
    sig: toBase64Url(sig),
  });
}

/**
 * Verify a served bundle (protocol v1, section 18.5). Reasons, in the order they are checked:
 * `size` (served text over 96 KiB, or decoded payload over 64 KiB), `schema` (not the
 * four-field JSON envelope, an unknown `alg`, bad base64url), `kid` (no pinned key with this
 * kid, the key is past `notAfter`, or its declared kid is not the hash of its public key: a
 * placeholder), `sig` (wrong length, S >= L, or the Ed25519 check over
 * `utf8("rg-policy-v1") 0x00 payloadBytes` fails), `schema` (the payload is not valid UTF-8
 * JSON for `PolicyBundlePayloadSchema`), `site` (another `siteId`, or another `siteKey` when
 * given), `rollback` (`version < minVersion`), `not-yet` (`notBefore` is more than 300 s ahead),
 * `expired` (`expiresAt + 300 s` has passed). A bad signature is never partially trusted.
 */
export async function verifyBundle(
  served: string,
  pinned: readonly PolicyKey[],
  now: number,
  minVersion: number,
  expect: { siteId: string; siteKey?: string },
): Promise<BundleResult> {
  if (typeof served !== 'string' || served.length > POLICY_LIMITS.maxServedBytes)
    return fail('size');
  let env: unknown;
  try {
    env = JSON.parse(served);
  } catch {
    return fail('schema');
  }
  if (typeof env !== 'object' || env === null || Array.isArray(env)) return fail('schema');
  const e = env as Record<string, unknown>;
  const keys = Object.keys(e);
  if (
    keys.length !== 4 ||
    typeof e.alg !== 'string' ||
    typeof e.kid !== 'string' ||
    typeof e.payload !== 'string' ||
    typeof e.sig !== 'string' ||
    !(POLICY_ALGS as readonly string[]).includes(e.alg)
  )
    return fail('schema');
  let bytes: Uint8Array;
  let sig: Uint8Array;
  try {
    bytes = fromBase64Url(e.payload);
    sig = fromBase64Url(e.sig);
  } catch {
    return fail('schema');
  }
  if (bytes.length > POLICY_LIMITS.maxBundleBytes) return fail('size');
  const key = pinnedSigner(pinned, e.kid, e.alg, now);
  if (key === undefined) return fail('kid');
  if (!(await verifyDomain(key, POLICY_SIGNATURE_DOMAIN, bytes, sig))) return fail('sig');

  let json: unknown;
  try {
    json = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    return fail('schema');
  }
  const parsed = PolicyBundlePayloadSchema.safeParse(json);
  if (!parsed.success) return fail('schema');
  const payload = parsed.data;
  const bad = checkVerifiedPayload(payload, now, minVersion, expect);
  if (bad !== null) return fail(bad);
  return { ok: true, payload, bytes };
}

/** The pinned key with this `kid` and `alg` that is consistent (its kid is the hash of its key) and not past `notAfter`. */
export function pinnedSigner(
  pinned: readonly PolicyKey[],
  kid: string,
  alg: string,
  now: number,
): PolicyKey | undefined {
  const key = pinned.find((k) => k.kid === kid && k.alg === alg);
  return key === undefined || !keyIsConsistent(key) || now > key.notAfter ? undefined : key;
}

/**
 * The checks that follow a good signature, in order: `site` (other `siteId`, or other `siteKey` when
 * given), `rollback`, `not-yet`, `expired`. The single copy: `verifyBundle` uses it, and so does a runtime
 * that re-uses an already verified payload from storage. With `allowStale` the expiry window is the 6 h
 * stale-while-error grace instead of the 300 s skew (a held bundle after a failed refresh).
 */
export function checkVerifiedPayload(
  payload: PolicyBundlePayload,
  now: number,
  minVersion: number,
  expect: { siteId: string; siteKey?: string },
  allowStale = false,
): BundleFailure | null {
  if (payload.siteId !== expect.siteId) return 'site';
  if (expect.siteKey !== undefined && payload.siteKey !== expect.siteKey) return 'site';
  if (payload.version < minVersion) return 'rollback';
  if (payload.notBefore > now + POLICY_LIMITS.clockSkewSeconds) return 'not-yet';
  const window = allowStale ? POLICY_LIMITS.staleGraceSeconds : POLICY_LIMITS.clockSkewSeconds;
  if (now > payload.expiresAt + window) return 'expired';
  return null;
}

/**
 * Where a cached, verified bundle stands at `now`: `fresh` (until `expiresAt` plus 300 s skew),
 * `grace` (stale-while-error, until `expiresAt` plus 6 h: keep serving the last good bundle) or
 * `expired` (the fail mode applies); `not-yet` if `notBefore` is more than 300 s ahead.
 */
export function bundleFreshness(
  p: Pick<PolicyBundlePayload, 'notBefore' | 'expiresAt'>,
  now: number,
): 'fresh' | 'grace' | 'expired' | 'not-yet' {
  if (p.notBefore > now + POLICY_LIMITS.clockSkewSeconds) return 'not-yet';
  if (now <= p.expiresAt + POLICY_LIMITS.clockSkewSeconds) return 'fresh';
  if (now <= p.expiresAt + POLICY_LIMITS.staleGraceSeconds) return 'grace';
  return 'expired';
}
