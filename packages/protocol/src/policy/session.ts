import { fromBase64Url, toBase64Url } from '../base64url.js';
import type { SessionState } from './decide.js';
import { requestHost } from './host.js';
import { POLICY_LIMITS, SESSION_SIGNATURE_DOMAIN } from './limits.js';
import type { PolicyKey } from './schema.js';
import { keyIsConsistent, signDomain, verifyDomain } from './sig.js';

export type TokenKey = PolicyKey;

export interface SessionClaims {
  /** Site id (UUID). */
  sid: string;
  /** Canonical host the token was issued for. */
  host: string;
  iat: number;
  exp: number;
  /** Hard maximum age in seconds from `iat`. */
  max: number;
  /** 0 session, 1 PoW clearance, 2 puzzle clearance. */
  lvl: 0 | 1 | 2;
  /** Score bucket 0-3. */
  sc: 0 | 1 | 2 | 3;
  /** Random id (16 to 32 base64url characters). */
  jti: string;
}

const encoder = new TextEncoder();
const JTI = /^[A-Za-z0-9_-]{16,32}$/;
const KID = /^[0-9a-f]{16}$/;
const CLAIM_KEYS = ['exp', 'host', 'iat', 'jti', 'lvl', 'max', 'sc', 'sid'];

/** `v1.<kid>.<payload b64url>.<sig b64url>`, signed over `utf8("rg-session-v1") 0x00 payloadBytes`. */
export async function mintSession(
  claims: SessionClaims,
  key: CryptoKey,
  kid: string,
): Promise<string> {
  const bytes = encoder.encode(JSON.stringify(claims));
  const sig = await signDomain(key, SESSION_SIGNATURE_DOMAIN, bytes);
  return `v1.${kid}.${toBase64Url(bytes)}.${toBase64Url(sig)}`;
}

/** Same as `mintSession` for raw payload bytes (the vector generator). */
export async function mintSessionBytes(
  bytes: Uint8Array,
  key: CryptoKey,
  kid: string,
): Promise<string> {
  const sig = await signDomain(key, SESSION_SIGNATURE_DOMAIN, bytes);
  return `v1.${kid}.${toBase64Url(bytes)}.${toBase64Url(sig)}`;
}

const INVALID: SessionState = { kind: 'invalid' };

/**
 * Verify a session or clearance token offline (protocol v1, section 18.6). An absent token
 * (null, undefined or "") is `none`; every failure is `invalid`, and the caller then treats the
 * request as having no session (no siteverify call is made for it). The token must: be at most
 * 4096 characters with the shape `v1.<kid>.<payload>.<sig>`; name a key in `keys` that is not
 * past `notAfter`; verify; carry exactly the claims `sid host iat exp max lvl sc jti` with the
 * right types; have `sid` equal to the expected site, `host` equal to the canonical request
 * host, `iat` not more than 300 s ahead, `now < exp`, `exp <= iat + max`, `now <= iat + max`,
 * `iat >= minIat` and a `jti` that is not in `revokedJti`. Async because WebCrypto is.
 */
export async function verifySession(
  token: string | null | undefined,
  keys: readonly TokenKey[],
  expect: { siteId: string; host: string },
  b: { minIat: number; revokedJti: readonly string[] },
  now: number,
): Promise<SessionState> {
  if (token === null || token === undefined || token === '') return { kind: 'none' };
  if (typeof token !== 'string' || token.length > POLICY_LIMITS.maxSessionTokenLength)
    return INVALID;
  const parts = token.split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') return INVALID;
  const [, kid, p, s] = parts as [string, string, string, string];
  if (!KID.test(kid)) return INVALID;
  const key = keys.find((k) => k.kid === kid);
  if (key === undefined || !keyIsConsistent(key) || now > key.notAfter) return INVALID;
  let bytes: Uint8Array;
  let sig: Uint8Array;
  try {
    bytes = fromBase64Url(p);
    sig = fromBase64Url(s);
  } catch {
    return INVALID;
  }
  if (!(await verifyDomain(key, SESSION_SIGNATURE_DOMAIN, bytes, sig))) return INVALID;
  let c: Record<string, unknown>;
  try {
    const j: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (typeof j !== 'object' || j === null || Array.isArray(j)) return INVALID;
    c = j as Record<string, unknown>;
  } catch {
    return INVALID;
  }
  if (Object.keys(c).sort().join() !== CLAIM_KEYS.join()) return INVALID;
  const int = (x: unknown): x is number =>
    typeof x === 'number' && Number.isSafeInteger(x) && x >= 0;
  const { sid, host, iat, exp, max, lvl, sc, jti } = c;
  if (typeof sid !== 'string' || typeof host !== 'string' || typeof jti !== 'string')
    return INVALID;
  if (!int(iat) || !int(exp) || !int(max) || max < 1 || max > 86400) return INVALID;
  if (lvl !== 0 && lvl !== 1 && lvl !== 2) return INVALID;
  if (sc !== 0 && sc !== 1 && sc !== 2 && sc !== 3) return INVALID;
  if (!JTI.test(jti)) return INVALID;
  const want = requestHost(expect.host);
  if (sid !== expect.siteId || want === null || host !== want) return INVALID;
  if (iat > now + POLICY_LIMITS.clockSkewSeconds) return INVALID;
  if (now >= exp || exp > iat + max || now > iat + max) return INVALID;
  if (iat < b.minIat || b.revokedJti.includes(jti)) return INVALID;
  return { kind: 'valid', lvl, sc };
}
