import {
  checkVerifiedPayload,
  fromBase64Url,
  POLICY_LIMITS,
  type PolicyBundlePayload,
  type PolicyKey,
  pinnedSigner,
  verifyBundle,
} from '@revokegpt/protocol';
import { MemoryVersionStore, type VerifiedCache, type VersionStore } from './config.js';

export interface BundleCacheOptions {
  url: string;
  siteKey: string;
  pinned: readonly PolicyKey[];
  fetch: typeof fetch;
  /** Milliseconds. */
  now: () => number;
  store?: VersionStore;
  /** Default 60000 ms plus up to a third of that (20 s) of jitter. */
  refreshMs?: number;
  random?: () => number;
  timeoutMs?: number;
  /** Always check the bundle's siteKey (production). False only for the test-only non-canonical key. */
  strictSiteKey?: boolean;
  /** Storage for verified payloads (see `FirewallConfig.verifiedCache`). */
  verifiedCache?: VerifiedCache;
  /** The site secret now. Sent as `Authorization: Bearer` on the bundle fetch (private bundles need it), to this `url` only. */
  secretKey?: () => string | undefined;
  /** Called once per process when the API refuses the bundle fetch with 401 or 403 (a configuration error). */
  onAuthError?: (status: number) => void;
}

const RETRY_MS = 10_000;

/**
 * Holds the last verified bundle. Single-flight refresh; refetch after the interval plus jitter
 * (the request that finds it due is answered from the held bundle while the refresh runs). A
 * refresh that fails, or returns a bundle that does not verify (bad signature, other site, lower
 * version, expired), keeps the last good bundle: it is served until `expiresAt` plus 6 h, after
 * which `decide` applies the bundle's fail mode itself. A bad signature is never partially trusted.
 */
export class BundleCache {
  readonly #o: BundleCacheOptions;
  readonly #store: VersionStore;
  #held: PolicyBundlePayload | null = null;
  #nextAt = 0;
  #siteId: string | null = null;
  #inflight: Promise<void> | null = null;
  #noPolicies = false;
  #authReported = false;

  constructor(o: BundleCacheOptions) {
    this.#o = o;
    this.#store = o.store ?? new MemoryVersionStore();
  }

  /**
   * The held bundle, or null if none was ever verified. Cold: the request that starts the first fetch
   * waits for it; a request that arrives while it is in flight does not queue behind it, it gets null
   * (the caller applies the initial fail mode). `waitUntil` keeps a background refresh alive on runtimes
   * that cancel work after the response (Workers, Compute).
   */
  async get(waitUntil?: (p: Promise<unknown>) => void): Promise<PolicyBundlePayload | null> {
    if (this.#held === null) {
      // After a failed fetch, retry only when the backoff is over.
      if (this.#inflight === null && this.#o.now() >= this.#nextAt) await this.refresh();
      return this.#held;
    }
    if (this.#o.now() >= this.#nextAt) {
      const p = this.refresh();
      try {
        waitUntil?.(p);
      } catch {
        // a runtime hook never changes a decision
      }
    }
    return this.#held;
  }

  /** True when the API answered an authentic 404 (no published policies) and no bundle is held. */
  get noPolicies(): boolean {
    return this.#held === null && this.#noPolicies;
  }

  /** Fetches and verifies now. Concurrent calls share one fetch. Never rejects. */
  refresh(): Promise<void> {
    if (this.#inflight === null) {
      this.#inflight = this.#doRefresh().finally(() => {
        this.#inflight = null;
      });
    }
    return this.#inflight;
  }

  /** Resolves when no refresh is running (tests). */
  async settle(): Promise<void> {
    while (this.#inflight !== null) await this.#inflight;
  }

  async #doRefresh(): Promise<void> {
    const t = this.#o.now();
    const base = this.#o.refreshMs ?? 60_000;
    const jitter = Math.floor(((this.#o.random ?? Math.random)() * base) / 3);
    this.#nextAt = t + RETRY_MS;
    this.#noPolicies = false; // only an authentic 404 in this very round sets it
    try {
      const served = await this.#fetchServed();
      if (served === 404) {
        this.#noPolicies = true;
        this.#nextAt = t + base + jitter;
        return;
      }
      const now = Math.floor(t / 1000);
      if (served === null) {
        // An outage: a runtime without a long-lived process picks the last verified bundle up from storage.
        await this.#restoreLastGood(now);
        return;
      }
      let siteId = this.#siteId ?? (await this.#hintedSiteId());
      if (siteId === null) {
        // First bundle: learn the site id from the payload. This trusts nothing: verifyBundle
        // below checks the signature over these same bytes against the pinned keys, and the
        // site key against the one configured.
        siteId = peekSiteId(served);
        if (siteId === null) return;
      }
      const min = Math.max(this.#held?.version ?? 0, await this.#store.get(siteId));
      // A key that is not in the canonical 20-character shape cannot appear in a signed bundle
      // (the schema refuses it); only then is the site pinned by id alone (conformance fixtures).
      const expect = {
        siteId,
        ...(this.#o.strictSiteKey === false ? {} : { siteKey: this.#o.siteKey }),
      };
      const payload = await this.#verified(served, now, min, expect);
      if (payload === null) {
        if (this.#held === null) await this.#restoreLastGood(now);
        return;
      }
      this.#noPolicies = false;
      this.#siteId = payload.siteId;
      this.#held = payload;
      this.#nextAt = t + base + jitter;
      await this.#store.put(payload.siteId, payload.version);
    } catch {
      // keep the last good bundle
    }
  }

  /** The payload of a served bundle: from storage if a valid entry exists, else by full verification (then stored). */
  async #verified(
    served: string,
    now: number,
    min: number,
    expect: { siteId: string; siteKey?: string },
  ): Promise<PolicyBundlePayload | null> {
    const cache = this.#o.verifiedCache;
    if (cache === undefined) {
      const r = await verifyBundle(served, this.#o.pinned, now, min, expect);
      return r.ok ? r.payload : null;
    }
    const fp = await fingerprint(this.#o.pinned);
    const key = `rg:bundle:${fp}:${await sha256Hex(served)}`;
    const hit = await this.#readEntry(key, key, now, min, expect, false);
    if (hit !== null) return hit;
    const r = await verifyBundle(served, this.#o.pinned, now, min, expect);
    if (!r.ok) return null;
    try {
      const env = JSON.parse(served) as { kid: string; alg: string };
      const body = JSON.stringify(r.payload);
      const head: Head = { k: key, kid: env.kid, alg: env.alg, d: await sha256Hex(body) };
      await cache.set(key, `${JSON.stringify(head)}\n${body}`);
      await cache.set(`rg:last:${fp}:${this.#o.siteKey}`, key);
      await cache.set(`rg:siteid:${this.#o.siteKey}`, r.payload.siteId);
    } catch {
      // storage is an optimisation; a failed write loses nothing
    }
    return r.payload;
  }

  /** Reads and fully re-checks a stored entry. Anything wrong with it is a miss (null), never an acceptance. */
  async #readEntry(
    storeKey: string,
    boundKey: string,
    now: number,
    min: number,
    expect: { siteId: string; siteKey?: string },
    allowStale: boolean,
  ): Promise<PolicyBundlePayload | null> {
    const cache = this.#o.verifiedCache;
    if (cache === undefined) return null;
    try {
      const text = await cache.get(storeKey);
      if (typeof text !== 'string') return null;
      // Two lines: a header, then the payload JSON exactly as it was hashed when it was stored.
      const nl = text.indexOf('\n');
      if (nl < 0) return null;
      const e = JSON.parse(text.slice(0, nl)) as Partial<Head>;
      // The entry must be the one made for exactly these served bytes, signed by a key that is still pinned.
      if (e.k !== boundKey || typeof e.kid !== 'string' || typeof e.alg !== 'string') return null;
      if (pinnedSigner(this.#o.pinned, e.kid, e.alg, now) === undefined) return null;
      const body = text.slice(nl + 1);
      if (e.d !== (await sha256Hex(body))) return null; // corrupted or edited in storage
      const p = JSON.parse(body) as PolicyBundlePayload;
      if (!hasPayloadShape(p)) return null;
      if (checkVerifiedPayload(p, now, min, expect, allowStale) !== null) return null;
      return p;
    } catch {
      return null;
    }
  }

  async #hintedSiteId(): Promise<string | null> {
    try {
      const v = await this.#o.verifiedCache?.get(`rg:siteid:${this.#o.siteKey}`);
      return typeof v === 'string' && SITE_ID.test(v) ? v : null;
    } catch {
      return null;
    }
  }

  /** After a failed refresh with nothing held: the last verified bundle, until `expiresAt` plus the 6 h grace. */
  async #restoreLastGood(now: number): Promise<void> {
    const cache = this.#o.verifiedCache;
    if (cache === undefined || this.#held !== null) return;
    try {
      const siteId = this.#siteId ?? (await this.#hintedSiteId());
      if (siteId === null) return;
      const key = await cache.get(
        `rg:last:${await fingerprint(this.#o.pinned)}:${this.#o.siteKey}`,
      );
      if (typeof key !== 'string') return;
      const min = await this.#store.get(siteId);
      const expect = {
        siteId,
        ...(this.#o.strictSiteKey === false ? {} : { siteKey: this.#o.siteKey }),
      };
      const p = await this.#readEntry(key, key, now, min, expect, true);
      if (p !== null) {
        this.#siteId = p.siteId;
        this.#held = p;
      }
    } catch {
      // nothing to restore
    }
  }

  async #fetchServed(): Promise<string | 404 | null> {
    try {
      const secret = this.#o.secretKey?.();
      const auth: Record<string, string> =
        secret === undefined || secret === '' ? {} : { authorization: `Bearer ${secret}` };
      let res = await this.#get({ accept: 'application/json', ...auth });
      if (res.status === 304) {
        // We never send a validator, so a 304 is an intermediary answering from a copy it no longer
        // holds: refetch once, asking every cache on the way to go to the origin.
        void res.body?.cancel().catch(() => {});
        res = await this.#get({
          accept: 'application/json',
          'cache-control': 'no-cache',
          pragma: 'no-cache',
          ...auth,
        });
      }
      if (res.status === 404) {
        void res.body?.cancel().catch(() => {});
        return 404;
      }
      if (res.status !== 200) {
        void res.body?.cancel().catch(() => {});
        if ((res.status === 401 || res.status === 403) && !this.#authReported) {
          this.#authReported = true;
          try {
            this.#o.onAuthError?.(res.status);
          } catch {
            // a logger never changes the outcome
          }
        }
        return null;
      }
      return await readCappedText(res, POLICY_LIMITS.maxServedBytes);
    } catch {
      return null;
    }
  }

  #get(headers: Record<string, string>): Promise<Response> {
    return this.#o.fetch(this.#o.url, {
      method: 'GET',
      headers,
      redirect: 'manual',
      signal: AbortSignal.timeout(this.#o.timeoutMs ?? 2000),
    });
  }
}

function peekSiteId(served: string): string | null {
  try {
    const env = JSON.parse(served) as { payload?: unknown };
    if (typeof env.payload !== 'string') return null;
    const p = JSON.parse(new TextDecoder().decode(fromBase64Url(env.payload))) as {
      siteId?: unknown;
    };
    return typeof p.siteId === 'string' ? p.siteId : null;
  } catch {
    return null;
  }
}

interface Head {
  k: string;
  kid: string;
  alg: string;
  /** SHA-256 of the payload text that follows the header. */
  d: string;
}

/**
 * The fields the post-signature checks and the engine rely on. The full schema parse already ran
 * before this payload was stored (re-running it costs about 20 ms in a Compute instance, which is
 * what the stored form avoids); the digest in the header catches corruption and edits.
 */
function hasPayloadShape(p: unknown): p is PolicyBundlePayload {
  const o = p as Record<string, unknown> | null;
  return (
    typeof o === 'object' &&
    o !== null &&
    typeof o.siteId === 'string' &&
    typeof o.siteKey === 'string' &&
    typeof o.version === 'number' &&
    typeof o.notBefore === 'number' &&
    typeof o.expiresAt === 'number' &&
    Array.isArray(o.policies) &&
    Array.isArray(o.tokenKeys) &&
    Array.isArray(o.hosts) &&
    Array.isArray(o.revokedJti) &&
    typeof o.session === 'object' &&
    o.session !== null
  );
}

const SITE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const hex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
async function sha256Hex(text: string, bytes = 32): Promise<string> {
  const d = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return hex(new Uint8Array(d).subarray(0, bytes));
}
/** A short hash of the pinned keys, so a stored payload is never reused after a key rotation. */
const fingerprint = (pinned: readonly PolicyKey[]): Promise<string> =>
  sha256Hex(
    pinned
      .map((k) => `${k.kid}:${k.alg}:${k.pub}:${k.notAfter}`)
      .sort()
      .join('\n'),
    8,
  );

/** The body as UTF-8 text, cut off (null) once it passes `max` bytes: counted while streaming, never buffered whole. */
async function readCappedText(res: Response, max: number): Promise<string | null> {
  if (res.body === null) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.length;
    if (n > max) {
      void reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(n);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.length;
  }
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(all);
}
