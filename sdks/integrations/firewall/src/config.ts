import { type PolicyKey, PRODUCTION_POLICY_KEYS, TEST_POLICY_KEYS } from '@revokegpt/protocol';

/** Remembers the highest bundle version seen per site, so a replayed older bundle is refused. */
export interface VersionStore {
  get(siteId: string): Promise<number>;
  put(siteId: string, version: number): Promise<void>;
}

/** In-process store: a restart forgets it (the in-memory cache's own high-water mark still holds). */
export class MemoryVersionStore implements VersionStore {
  readonly #v = new Map<string, number>();
  async get(siteId: string): Promise<number> {
    return this.#v.get(siteId) ?? 0;
  }
  async put(siteId: string, version: number): Promise<void> {
    if (version > (this.#v.get(siteId) ?? 0)) this.#v.set(siteId, version);
  }
}

/** Text storage for verified bundle payloads (see `FirewallConfig.verifiedCache`). */
export interface VerifiedCache {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
}

/** The only fields an integration may log (protocol v1 section 18.8). */
export interface LogEvent {
  decisionId: string;
  ruleIndex: number | null;
  action: string;
}

export interface FirewallConfig {
  /** The site key (`rgpk_...`); the bundle is fetched from `/v1/policies/<siteKey>`. */
  siteKey: string;
  /** The site secret (`rgsk_...`), sent as a Bearer token to siteverify. Without it a `requireToken` rule applies `onError`. */
  secretKey?: string | (() => string | undefined);
  /** Default `https://api.revokegpt.com`. Plain http is accepted only for localhost and 127.0.0.1. */
  apiBase?: string;
  /** Pinned bundle keys. Default `PRODUCTION_POLICY_KEYS`: the test keys are never trusted unless `pinTestKeys` is set (never by NODE_ENV). */
  pinnedKeys?: readonly PolicyKey[];
  /** `<name>/<version>`, sent as `X-RG-Integration`. */
  integration: string;
  /** Opt-in `X-RG-Sig` secret: HMAC-SHA256 over the decision headers, so an origin can tell the integration set them. */
  sigSecret?: string;
  fetch?: typeof fetch;
  /** Clock in milliseconds (like `Date.now`). */
  now?: () => number;
  store?: VersionStore;
  /** Receives `{decisionId, ruleIndex, action}` per request. Nothing else is ever logged. */
  log?: (e: LogEvent) => void;
  /** Before any bundle was ever verified (outage, or nothing fetched yet): `open` (default) passes with `X-RG-Verdict: none`, `closed` answers 503. An authentic 404 from the policies endpoint (no published policies) always passes. */
  initialFailMode?: 'open' | 'closed';
  /**
   * Test-only switch: also pins the TEST policy keys and accepts a non-canonical site key (the
   * conformance fixtures use `rgpk_conformance`). Without it the site key must be canonical and
   * the bundle's `siteKey` is always checked. Never set in production.
   */
  pinTestKeys?: boolean;
  /**
   * Optional storage for verified bundle payloads, for runtimes whose instances do not live long (one
   * request each). The core owns everything about it: the key (pinned-key fingerprint plus SHA-256 of the
   * exact served bytes), what is stored (only payloads that passed the full Ed25519 verification) and the
   * checks on a hit (entry bound to these exact bytes, digest, payload shape, pinned unexpired signer, site,
   * version floor, freshness; the full schema ran before the payload was stored). A value that is missing,
   * malformed, corrupted or stale can only cause a full verification, never an acceptance. The digest has no
   * secret, so whoever can write this storage can make the core trust a payload: the storage must be private
   * to the service (never shared across tenants or writable by anything else). Values are text of about
   * 64 KiB; keep them 30 hours or more.
   */
  verifiedCache?: VerifiedCache;
  /** Bundle refetch interval in ms. Default 60000 (plus 0 to 20 s of jitter). Lower values are for the conformance harness only. */
  bundleRefreshMs?: number;
}

export interface ResolvedConfig {
  siteKey: string;
  secretKey: (() => string | undefined) | null;
  apiBase: string;
  pinnedKeys: readonly PolicyKey[];
  integration: string;
  sigSecret: string | null;
  fetch: typeof fetch;
  now: () => number;
  store: VersionStore;
  log: (e: LogEvent) => void;
  initialFailMode: 'open' | 'closed';
  strictSiteKey: boolean;
  bundleRefreshMs: number;
  verifiedCache: VerifiedCache | undefined;
}

const DEFAULT_API = 'https://api.revokegpt.com';
const SITE_KEY_CANONICAL = /^rgpk_[0-9A-Za-z]{20}$/;
const SITE_KEY_TEST = /^rgpk_[0-9A-Za-z_]{1,64}$/;
const SECRET_SHAPE = /^rgsk_[0-9A-Za-z_]{1,128}$/;
const INTEGRATION_SHAPE = /^[A-Za-z0-9._-]{1,32}\/[A-Za-z0-9._+-]{1,32}$/;
const LOCAL = new Set(['localhost', '127.0.0.1', '[::1]']);

/** Validates the config and fills defaults. Throws `TypeError`; messages never include a key or URL. */
export function resolveConfig(cfg: FirewallConfig): ResolvedConfig {
  if (typeof cfg !== 'object' || cfg === null) throw new TypeError('invalid config');
  if (
    typeof cfg.siteKey !== 'string' ||
    !(cfg.pinTestKeys === true ? SITE_KEY_TEST : SITE_KEY_CANONICAL).test(cfg.siteKey)
  )
    throw new TypeError('invalid siteKey');
  if (typeof cfg.secretKey === 'string' && !SECRET_SHAPE.test(cfg.secretKey))
    throw new TypeError('invalid secretKey');
  if (typeof cfg.integration !== 'string' || !INTEGRATION_SHAPE.test(cfg.integration))
    throw new TypeError('invalid integration: expected <name>/<version>');
  let base: URL;
  try {
    base = new URL(cfg.apiBase ?? DEFAULT_API);
  } catch {
    throw new TypeError('invalid apiBase');
  }
  const okScheme =
    base.protocol === 'https:' || (base.protocol === 'http:' && LOCAL.has(base.hostname));
  if (!okScheme || base.username !== '' || base.password !== '' || base.search || base.hash)
    throw new TypeError('invalid apiBase: https required (http only for localhost)');
  if (cfg.pinTestKeys === true) {
    // Ruling 13: TEST keys only for the loopback conformance setup, never beside a real site key.
    if (SITE_KEY_CANONICAL.test(cfg.siteKey))
      throw new TypeError('pinTestKeys is refused with a canonical site key');
    if (!LOCAL.has(base.hostname))
      throw new TypeError(
        'pinTestKeys is refused unless apiBase is loopback (127.0.0.1, [::1], localhost)',
      );
  }
  if (
    cfg.sigSecret !== undefined &&
    (typeof cfg.sigSecret !== 'string' || cfg.sigSecret.length < 16)
  )
    throw new TypeError('invalid sigSecret');
  const fetchImpl = cfg.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new TypeError('no fetch implementation available');
  const refresh = cfg.bundleRefreshMs ?? 60_000;
  if (!Number.isInteger(refresh) || refresh < 1) throw new TypeError('invalid bundleRefreshMs');
  return {
    siteKey: cfg.siteKey,
    secretKey:
      typeof cfg.secretKey === 'function'
        ? () => {
            const v = (cfg.secretKey as () => string | undefined)();
            return typeof v === 'string' && SECRET_SHAPE.test(v) ? v : undefined;
          }
        : cfg.secretKey === undefined
          ? null
          : (() => {
              const fixed = cfg.secretKey;
              return () => fixed;
            })(),
    apiBase: base.origin,
    pinnedKeys:
      cfg.pinnedKeys ??
      (cfg.pinTestKeys === true
        ? [...PRODUCTION_POLICY_KEYS, ...TEST_POLICY_KEYS]
        : PRODUCTION_POLICY_KEYS),
    integration: cfg.integration,
    sigSecret: cfg.sigSecret ?? null,
    fetch: fetchImpl,
    now: cfg.now ?? Date.now,
    store: cfg.store ?? new MemoryVersionStore(),
    log: cfg.log ?? (() => {}),
    initialFailMode: cfg.initialFailMode ?? 'open',
    strictSiteKey: cfg.pinTestKeys !== true,
    bundleRefreshMs: refresh,
    verifiedCache: cfg.verifiedCache,
  };
}
