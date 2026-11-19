import { fromBase64Url } from './base64url.js';

export type PowParams = {
  algorithm: 'sha256-v1';
  /** base64url, 16 random bytes (the challenge id). */
  salt: string;
  /** 1..32 */
  difficultyBits: number;
  /** 1..256 */
  count: number;
};

export const POW_LIMITS = Object.freeze({
  saltBytes: 16,
  minBits: 1,
  maxBits: 32,
  minCount: 1,
  maxCount: 256,
  maxNonce: Number.MAX_SAFE_INTEGER,
} as const);

const PARAM_KEYS = ['algorithm', 'salt', 'difficultyBits', 'count'] as const;

export const POW_DOMAIN = 'rg-pow-v1';

const DOMAIN_BYTES = new TextEncoder().encode(POW_DOMAIN);
const SALT_OFFSET = DOMAIN_BYTES.length; // 9
const INDEX_OFFSET = SALT_OFFSET + POW_LIMITS.saltBytes; // 25
const NONCE_OFFSET = INDEX_OFFSET + 1; // 26
const INPUT_LENGTH = NONCE_OFFSET + 8; // 34

/** Number of leading zero bits in `b`. */
export function leadingZeroBits(b: Uint8Array): number {
  let bits = 0;
  for (const byte of b) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

function isInt(v: unknown, min: number, max: number): v is number {
  return typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;
}

/**
 * Validates params (treated as untrusted) and returns the decoded salt, or null. Only own
 * properties count (`Object.hasOwn`), so a polluted `Object.prototype` cannot supply a parameter.
 * Each property of `p` is read exactly once, so getters cannot return different values to
 * different checks.
 */
function parseParams(p: unknown): { salt: Uint8Array; bits: number; count: number } | null {
  if (typeof p !== 'object' || p === null) return null;
  for (const key of PARAM_KEYS) if (!Object.hasOwn(p, key)) return null;
  const { algorithm, salt, difficultyBits, count } = p as Record<string, unknown>;
  if (algorithm !== 'sha256-v1') return null;
  if (!isInt(difficultyBits, POW_LIMITS.minBits, POW_LIMITS.maxBits)) return null;
  if (!isInt(count, POW_LIMITS.minCount, POW_LIMITS.maxCount)) return null;
  if (typeof salt !== 'string') return null;
  let decoded: Uint8Array;
  try {
    decoded = fromBase64Url(salt);
  } catch {
    return null;
  }
  if (decoded.length !== POW_LIMITS.saltBytes) return null;
  return { salt: decoded, bits: difficultyBits, count };
}

function newInput(salt: Uint8Array): { buf: Uint8Array<ArrayBuffer>; view: DataView } {
  const buf = new Uint8Array(INPUT_LENGTH);
  buf.set(DOMAIN_BYTES, 0);
  buf.set(salt, SALT_OFFSET);
  return { buf, view: new DataView(buf.buffer) };
}

/**
 * Writes the sub-puzzle index into its single byte. Defensive: parseParams already caps `count` at
 * POW_LIMITS.maxCount (256), so an index above 255 is unreachable; if it were reached, the byte
 * would wrap and two sub-puzzles would share an input, so this throws instead.
 */
function setIndex(buf: Uint8Array, i: number): void {
  if (!Number.isInteger(i) || i < 0 || i > 0xff)
    throw new RangeError('sub-puzzle index exceeds u8');
  buf[INDEX_OFFSET] = i;
}

async function meets(buf: Uint8Array<ArrayBuffer>, bits: number): Promise<boolean> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
  return leadingZeroBits(digest) >= bits;
}

/**
 * Verifies a sha256-v1 proof-of-work solution. Never throws; attacker-supplied
 * `solutions` are shape-checked (length first) before any hashing.
 *
 * Hostile inputs: `p.count` is read once (inside parseParams), `solutions` is read by index from
 * 0 to `params.count` only (never iterated, so a Proxy cannot drive unbounded work), and its length
 * is re-asserted after the reads.
 *
 * PoW is a cost signal, not proof of humanity.
 */
export async function verifyPow(p: PowParams, solutions: unknown): Promise<boolean> {
  try {
    if (!Array.isArray(solutions)) return false;
    const params = parseParams(p);
    if (!params) return false;
    const count = params.count;
    if (solutions.length !== count) return false;
    const nonces: number[] = new Array(count);
    for (let i = 0; i < count; i++) {
      const n: unknown = solutions[i];
      if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < 0) return false;
      nonces[i] = n;
    }
    if (solutions.length !== count) return false;
    if (count > 256) throw new RangeError('count exceeds the one-byte index'); // unreachable
    const { buf, view } = newInput(params.salt);
    for (let i = 0; i < count; i++) {
      setIndex(buf, i);
      view.setBigUint64(NONCE_OFFSET, BigInt(nonces[i] as number));
      if (!(await meets(buf, params.bits))) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/** Reference/test solver: lowest valid nonce per sub-puzzle. Slow; use low difficulty only. */
export async function solvePow(p: PowParams): Promise<number[]> {
  const params = parseParams(p);
  if (!params) throw new TypeError('invalid PoW params');
  if (params.count > 256) throw new RangeError('count exceeds the one-byte index'); // unreachable
  const { buf, view } = newInput(params.salt);
  const out: number[] = [];
  for (let i = 0; i < params.count; i++) {
    setIndex(buf, i);
    let n = 0;
    for (;;) {
      if (n > POW_LIMITS.maxNonce) throw new RangeError('no nonce within POW_LIMITS.maxNonce');
      view.setBigUint64(NONCE_OFFSET, BigInt(n));
      if (await meets(buf, params.bits)) break;
      n++;
    }
    out.push(n);
  }
  return out;
}
