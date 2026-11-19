import { copyRegex, SITE_ID } from './patterns.js';

/**
 * Spend-store addressing (protocol v1 sections 8 and 9). Single use holds only if every request for
 * one spend key reaches the same strongly consistent object, so the Durable Object name is a pure
 * function of the site, the spend key and the shard count: never the caller's location, a random
 * pick or the time. In v1 the shard count is the protocol constant `SPEND_SHARDS` for every site,
 * and a site's jurisdiction never changes (a new jurisdiction is a new site with a new site key),
 * so a spend key maps to one object for the site's whole lifetime. `locationHint` chooses
 * placement only; it is not part of the name.
 */

/** Versioned domain-separation prefix of the shard hash input. */
export const SPEND_SHARD_DOMAIN = 'rg-spend-shard-v1';

/**
 * The spend shard count N of protocol v1: the same for every site and never changed for a site.
 * Every v1 caller passes it to `spendShardName`; another N is a different protocol version.
 */
export const SPEND_SHARDS = 16;

/**
 * Spend records are domain-separated by kind: the stored spend key is ASCII `c:` + challenge id or
 * ASCII `t:` + `token_id`, so a challenge spend and a token spend never share a record.
 */
export const SPEND_KINDS = Object.freeze({ challenge: 'c:', token: 't:' } as const);
export type SpendKind = keyof typeof SPEND_KINDS;

export const SPEND_SHARD_LIMITS = Object.freeze({
  minShards: 1,
  maxShards: 65536,
  /** A challenge id and a `token_id` are both 16 bytes. */
  idBytes: 16,
  /** Two prefix bytes plus the id. */
  keyBytes: 18,
} as const);

/**
 * A site id: the site's UUID in lowercase canonical text form, nothing else (no uppercase, braces,
 * URN prefix or missing hyphens), so one site has exactly one object name. A public copy.
 */
export const SITE_ID_RE: RegExp = copyRegex(SITE_ID);

const DOMAIN_BYTES = new TextEncoder().encode(SPEND_SHARD_DOMAIN);
const C = 0x63; // 'c'
const T = 0x74; // 't'
const COLON = 0x3a;

/** A copy of `id` (by its internal length), checked to be exactly 16 bytes. */
function copyId(id: unknown): Uint8Array<ArrayBuffer> {
  if (!(id instanceof Uint8Array)) throw new TypeError('id must be a Uint8Array');
  const copy = new Uint8Array(id);
  if (copy.byteLength !== SPEND_SHARD_LIMITS.idBytes)
    throw new RangeError('id must be exactly 16 bytes');
  return copy;
}

/**
 * The spend key for a challenge or a token: ASCII `c:` or `t:` followed by the 16-byte challenge id
 * or `token_id` (18 bytes). This is the key passed to `spendShardName` and stored in the object.
 * Throws TypeError for any other kind (compared exactly, so `constructor` or `__proto__` cannot
 * select an inherited value) or a non-Uint8Array id, and RangeError unless the id is 16 bytes. The
 * id is copied, so changing the caller's array later does not change the key.
 */
export function makeSpendKey(kind: SpendKind, id: Uint8Array): Uint8Array {
  let first: number;
  if (kind === 'challenge') first = C;
  else if (kind === 'token') first = T;
  else throw new TypeError("kind must be 'challenge' or 'token'");
  const copy = copyId(id);
  const key = new Uint8Array(SPEND_SHARD_LIMITS.keyBytes);
  key[0] = first;
  key[1] = COLON;
  key.set(copy, 2);
  return key;
}

/**
 * The Durable Object name for a spend key: `spend:<siteId>:<shard>`, where `shard` is the first 4
 * bytes of SHA-256(ASCII "rg-spend-shard-v1" || u8 len(siteId) || ASCII siteId || spendKey), read as
 * an unsigned 32-bit big-endian integer, modulo `shards`. Deterministic: the same inputs give the
 * same name in every runtime. A v1 server passes `SPEND_SHARDS` as `shards`; any other count is
 * accepted only so that ports can check the modulo arithmetic (`test-vectors/spend.json`), never
 * to change a site's mapping (v1.md section 9).
 *
 * `siteId` must match `SITE_ID_RE` (lowercase canonical UUID), else TypeError. `spendKey` must be a
 * key from `makeSpendKey`: a Uint8Array of exactly 18 bytes starting with `c:` or `t:` (TypeError
 * for a non-Uint8Array or another prefix, RangeError for another length). `shards` must be an
 * integer from 1 to 65536 (RangeError). The key is copied first (by its internal length), so a
 * subclass that lies through a `length` getter cannot change what is hashed. Uses WebCrypto, so it
 * is asynchronous.
 */
export async function spendShardName(
  siteId: string,
  spendKey: Uint8Array,
  shards: number,
): Promise<string> {
  if (
    typeof shards !== 'number' ||
    !Number.isInteger(shards) ||
    shards < SPEND_SHARD_LIMITS.minShards ||
    shards > SPEND_SHARD_LIMITS.maxShards
  )
    throw new RangeError('shards must be an integer from 1 to 65536');
  if (typeof siteId !== 'string' || !SITE_ID.test(siteId))
    throw new TypeError('siteId must be a lowercase canonical UUID');
  if (!(spendKey instanceof Uint8Array)) throw new TypeError('spendKey must be a Uint8Array');
  const key = new Uint8Array(spendKey);
  if (key.byteLength !== SPEND_SHARD_LIMITS.keyBytes)
    throw new RangeError('spendKey must be 18 bytes (from makeSpendKey)');
  if ((key[0] !== C && key[0] !== T) || key[1] !== COLON)
    throw new TypeError('spendKey must start with c: or t: (from makeSpendKey)');
  const input = new Uint8Array(DOMAIN_BYTES.length + 1 + siteId.length + key.length);
  input.set(DOMAIN_BYTES, 0);
  input[DOMAIN_BYTES.length] = siteId.length;
  for (let i = 0; i < siteId.length; i++) input[DOMAIN_BYTES.length + 1 + i] = siteId.charCodeAt(i);
  input.set(key, DOMAIN_BYTES.length + 1 + siteId.length);
  const digest = new DataView(await globalThis.crypto.subtle.digest('SHA-256', input));
  return `spend:${siteId}:${digest.getUint32(0) % shards}`;
}
