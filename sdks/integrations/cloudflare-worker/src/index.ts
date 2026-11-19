/**
 * RevokeGPT firewall as a Cloudflare Worker (protocol v1 section 18). A template that fronts an origin:
 * every request goes through `createFirewall` from `@revokegpt/firewall`; an allowed request is
 * forwarded (`fetch(request)` on a route, or to `RG_ORIGIN`), anything else is answered here.
 *
 * Env: vars `RG_SITE_KEY`, `RG_API_BASE`; secret `RG_SECRET_KEY`; optional `RG_STATE` (KV: highest bundle
 * version per site), `RG_ORIGIN`, `RG_SIG_SECRET`, `RG_INITIAL_FAIL_MODE`, `RG_BUNDLE_REFRESH_MS`, and
 * `RG_PIN_TEST_KEYS=1` (conformance only: Workers have no NODE_ENV, so the switch is a var; it is refused
 * unless the site key is non-canonical AND the API base is loopback).
 */
import { AsyncLocalStorage } from 'node:async_hooks';
import {
  createFirewall,
  type Firewall,
  type FwRequest,
  type FwResult,
  MemoryVersionStore,
  type VersionStore,
} from '@revokegpt/firewall';

export interface RgEnv {
  RG_SITE_KEY: string;
  RG_API_BASE?: string;
  RG_SECRET_KEY?: string;
  RG_SIG_SECRET?: string;
  RG_ORIGIN?: string;
  RG_INITIAL_FAIL_MODE?: string;
  RG_BUNDLE_REFRESH_MS?: string;
  RG_PIN_TEST_KEYS?: string;
  RG_STATE?: KVNamespace;
}

const INTEGRATION = 'cloudflare-worker/1.0.0';
const MAX_FORM_BYTES = 4096;
/** Cap on how long a request is kept alive waiting for a background bundle refresh to finish. */
const REFRESH_KEEPALIVE_MS = 3000;
const BUNDLE_CACHE_SECONDS = 86_400;

/** The execution context of the request that is running, so the core's background refresh can use `waitUntil`. */
const current = new AsyncLocalStorage<ExecutionContext>();

/**
 * Per-firewall refresh state. The core refreshes single-flight, so at most one refresh is in flight per
 * firewall; its keep-alive and its not-yet-verified bundle copy live here, never in a module global, so a
 * request on another firewall can neither release this keep-alive nor have its bundle cached by us.
 */
class RefreshState {
  #release: (() => void) | null = null;
  #pending: { url: string; text: string; ctx: ExecutionContext } | null = null;

  /** Registers a keep-alive with the running request's `waitUntil`; replaces (releases) this firewall's previous one. */
  hold(): void {
    const ctx = current.getStore();
    if (ctx === undefined) return;
    this.release();
    let timer: ReturnType<typeof setTimeout>;
    let release: () => void = () => {};
    const done = new Promise<void>((resolve) => {
      release = (): void => {
        clearTimeout(timer);
        if (this.#release === release) this.#release = null;
        resolve();
      };
      timer = setTimeout(release, REFRESH_KEEPALIVE_MS);
    });
    this.#release = release;
    try {
      ctx.waitUntil(done);
    } catch {
      release();
    }
  }

  release(): void {
    this.#release?.();
  }

  /** A 200 body the core has not verified yet. */
  stage(url: string, text: string): void {
    const ctx = current.getStore();
    this.#pending = ctx === undefined ? null : { url, text, ctx };
  }

  discard(): void {
    this.#pending = null;
  }

  /** The core verified the staged bundle (it only stores a version after verification): now it may be cached. */
  commit(): void {
    const p = this.#pending;
    this.#pending = null;
    if (p !== null) {
      const cache = (caches as unknown as { default: Cache }).default;
      const copy = new Response(p.text, {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': `public, max-age=${BUNDLE_CACHE_SECONDS}`,
        },
      });
      try {
        p.ctx.waitUntil(cache.put(p.url, copy).catch(() => {}));
      } catch {
        // no cache copy this time
      }
    }
    this.release();
  }
}

/** Version store (KV when bound, else in the isolate) that tells `state` when the core has verified a bundle. */
class NotifyingStore implements VersionStore {
  constructor(
    private readonly inner: VersionStore,
    private readonly state: RefreshState,
  ) {}
  get(siteId: string): Promise<number> {
    return this.inner.get(siteId);
  }
  async put(siteId: string, version: number): Promise<void> {
    try {
      await this.inner.put(siteId, version);
    } finally {
      this.state.commit();
    }
  }
}

class KvVersionStore implements VersionStore {
  constructor(private readonly kv: KVNamespace) {}
  async get(siteId: string): Promise<number> {
    const v = Number(await this.kv.get(`rg:v:${siteId}`));
    return Number.isSafeInteger(v) && v > 0 ? v : 0;
  }
  async put(siteId: string, version: number): Promise<void> {
    if (version > (await this.get(siteId))) await this.kv.put(`rg:v:${siteId}`, String(version));
  }
}

/**
 * Bundle fetches: network first; a network failure or a non-200/404 answer falls back to the Cache API copy
 * (colo-wide, shared by isolates). The core still verifies the signature, expiry and version of whatever it
 * is given. A 200 is only written to the cache after the core verified it (`RefreshState.commit`), so a bad
 * 200 never overwrites the last good copy. An authentic 404 is never answered from the cache.
 */
function bundleFetch(state: RefreshState): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input instanceof Request ? input.url : input);
    if (!url.includes('/v1/policies/')) return globalThis.fetch(input, init);
    state.hold();
    state.discard();
    const cache = (caches as unknown as { default: Cache }).default;
    const fallback = async (): Promise<Response> => {
      state.release();
      const hit = await cache.match(url).catch(() => undefined);
      return hit ?? new Response('', { status: 503 });
    };
    let res: Response;
    try {
      res = await globalThis.fetch(input, init);
    } catch {
      return fallback();
    }
    if (res.status === 404) {
      state.release();
      return res;
    }
    if (res.status !== 200) {
      void res.body?.cancel().catch(() => {});
      return fallback();
    }
    try {
      state.stage(url, await res.clone().text());
    } catch {
      state.discard();
    }
    return res;
  }) as typeof fetch;
}

const firewalls = new Map<string, Firewall>();

function firewallFor(env: RgEnv): Firewall {
  const key = JSON.stringify([
    env.RG_SITE_KEY,
    env.RG_API_BASE,
    env.RG_SECRET_KEY,
    env.RG_SIG_SECRET,
    env.RG_INITIAL_FAIL_MODE,
    env.RG_BUNDLE_REFRESH_MS,
    env.RG_PIN_TEST_KEYS,
    env.RG_STATE !== undefined,
  ]);
  const held = firewalls.get(key);
  if (held !== undefined) return held;
  const refresh = Number(env.RG_BUNDLE_REFRESH_MS);
  const mode = env.RG_INITIAL_FAIL_MODE;
  if (mode !== undefined && mode !== 'open' && mode !== 'closed')
    throw new TypeError('invalid RG_INITIAL_FAIL_MODE');
  const state = new RefreshState();
  const fw = createFirewall({
    siteKey: env.RG_SITE_KEY,
    ...(env.RG_SECRET_KEY ? { secretKey: env.RG_SECRET_KEY } : {}),
    ...(env.RG_API_BASE ? { apiBase: env.RG_API_BASE } : {}),
    ...(env.RG_SIG_SECRET ? { sigSecret: env.RG_SIG_SECRET } : {}),
    ...(mode ? { initialFailMode: mode } : {}),
    ...(env.RG_BUNDLE_REFRESH_MS ? { bundleRefreshMs: refresh } : {}),
    ...(env.RG_PIN_TEST_KEYS === '1' ? { pinTestKeys: true } : {}),
    integration: INTEGRATION,
    fetch: bundleFetch(state),
    store: new NotifyingStore(
      env.RG_STATE === undefined ? new MemoryVersionStore() : new KvVersionStore(env.RG_STATE),
      state,
    ),
  });
  firewalls.set(key, fw);
  return fw;
}

/** Parses the Cookie header. A name that appears twice is dropped: which copy the browser meant is unknowable. */
function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  const dup = new Set<string>();
  if (header === null) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const name = part.slice(0, i).trim();
    if (name === '' || name === '__proto__') continue;
    if (name in out) dup.add(name);
    else out[name] = part.slice(i + 1).trim();
  }
  for (const n of dup) delete out[n];
  return out;
}

/** Reads at most `MAX_FORM_BYTES + 1` bytes so an oversize body is detected without buffering it all. */
async function boundedText(request: Request): Promise<string> {
  if (request.body === null) return '';
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (total <= MAX_FORM_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.byteLength;
  }
  void reader.cancel().catch(() => {});
  const all = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(all);
}

function toFwRequest(request: Request, url: URL): FwRequest {
  return {
    method: request.method,
    host: request.headers.get('host') ?? url.host,
    // Workers hand us a parsed URL: this is the target as workerd normalised it (see README).
    rawTarget: url.pathname + url.search,
    headers: [...request.headers.entries()],
    cookies: parseCookies(request.headers.get('cookie')),
    body: () => boundedText(request),
  };
}

function answer(r: Extract<FwResult, { type: 'respond' }>): Response {
  const headers = new Headers();
  for (const [n, v] of r.headers) headers.append(n, v);
  return new Response(r.body === '' || r.status === 204 ? null : r.body, {
    status: r.status,
    headers,
  });
}

async function forward(request: Request, url: URL, env: RgEnv, r: FwResult): Promise<Response> {
  if (r.type === 'respond') return answer(r);
  // Strip every x-rg-* the client sent, then set only what the engine decided. Never copied into responses.
  const headers = new Headers(request.headers);
  for (const n of r.stripHeaders) headers.delete(n);
  for (const [n, v] of Object.entries(r.setHeaders)) headers.set(n, v);
  const hasBody = request.method !== 'GET' && request.method !== 'HEAD';
  let target = request.url;
  if (env.RG_ORIGIN) {
    const o = new URL(env.RG_ORIGIN);
    target = `${o.origin}${url.pathname}${url.search}`;
  }
  return fetch(
    new Request(target, {
      method: request.method,
      headers,
      body: hasBody ? request.body : null,
      redirect: 'manual',
    }),
  );
}

export default {
  async fetch(request: Request, env: RgEnv, ctx: ExecutionContext): Promise<Response> {
    return current.run(ctx, async () => {
      let fw: Firewall;
      try {
        fw = firewallFor(env);
      } catch {
        // A start-up config error: never open, never leak which setting is wrong.
        return new Response('Service Unavailable', {
          status: 503,
          headers: { 'Cache-Control': 'no-store' },
        });
      }
      const url = new URL(request.url);
      const out = await fw.handle(toFwRequest(request, url));
      return forward(request, url, env, out);
    });
  },
} satisfies ExportedHandler<RgEnv>;
