import { fromBase64Url } from '../base64url.js';
import { sha256 } from '../sha256.js';
import { POLICY_ALGS } from './limits.js';
import type { PolicyKey } from './schema.js';

const encoder = new TextEncoder();

/** The Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493. */
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

/** `kid`: the first 8 bytes of SHA-256(raw public key) as 16 lower-case hex characters. */
export function kidOfPublicKey(rawPublicKey: Uint8Array): string {
  const h = sha256(rawPublicKey);
  let out = '';
  for (let i = 0; i < 8; i++) out += (h[i] as number).toString(16).padStart(2, '0');
  return out;
}

/**
 * True if the second half of a 64-byte Ed25519 signature (S, little-endian) is below the group
 * order L. RFC 8032 requires it; WebCrypto, OpenSSL and libsodium reject S >= L, but a port
 * whose library does not would accept a malleated signature, so every port checks it itself,
 * before the library call (vector `sig-non-canonical-s` in policy.json).
 */
export function isCanonicalS(sig: Uint8Array): boolean {
  if (sig.length !== 64) return false;
  let s = 0n;
  for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i] as number);
  return s < L;
}

function domainBytes(domain: string, payload: Uint8Array): Uint8Array {
  const d = encoder.encode(domain);
  const out = new Uint8Array(d.length + payload.length);
  out.set(d);
  out.set(payload, d.length);
  return out;
}

/** Sign `domain || payload` (domain includes its NUL byte) with an Ed25519 private key. */
export async function signDomain(
  key: CryptoKey,
  domain: string,
  payload: Uint8Array,
): Promise<Uint8Array> {
  const sig = await globalThis.crypto.subtle.sign(
    { name: 'Ed25519' },
    key,
    domainBytes(domain, payload) as BufferSource,
  );
  return new Uint8Array(sig);
}

/**
 * Verify `domain || payload` under a pinned or token key: the key must be Ed25519 (the only
 * algorithm in POLICY_ALGS), its kid must be the real kid of its public key, and the signature
 * must be 64 bytes with a canonical S. Never throws; false on any failure.
 */
export async function verifyDomain(
  key: PolicyKey,
  domain: string,
  payload: Uint8Array,
  sigBytes: Uint8Array,
): Promise<boolean> {
  try {
    if (!(POLICY_ALGS as readonly string[]).includes(key.alg)) return false;
    if (!isCanonicalS(sigBytes)) return false;
    const pub = fromBase64Url(key.pub);
    if (pub.length !== 32) return false;
    const k = await globalThis.crypto.subtle.importKey(
      'raw',
      pub as BufferSource,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    return await globalThis.crypto.subtle.verify(
      { name: 'Ed25519' },
      k,
      sigBytes as BufferSource,
      domainBytes(domain, payload) as BufferSource,
    );
  } catch {
    return false;
  }
}

/** True if the key's declared `kid` is the real kid of its public key (placeholders are not). */
export function keyIsConsistent(key: PolicyKey): boolean {
  try {
    const pub = fromBase64Url(key.pub);
    return pub.length === 32 && kidOfPublicKey(pub) === key.kid;
  } catch {
    return false;
  }
}
