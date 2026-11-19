import type { LoadOptions, Locale, RevokeGPTApi } from './types.js';

/** The default widget origin (a placeholder until the final domain is set). */
export const DEFAULT_ORIGIN = 'https://js.revokegpt.com';
export const LOAD_TIMEOUT_MS = 15_000;

const LOCALES: ReadonlySet<string> = new Set(
  'en es fr de it pt-BR pt-PT nl pl ru uk tr ar he fa hi bn id ms vi th ja ko zh-CN zh-TW sv cs el'.split(
    ' ',
  ),
);
const LOAD_KEY = Symbol.for('revokegpt.load');
const SCRIPT_PATH = '/v1/api.js';
// Replaced by bundlers; where there is no `process`, the page counts as production.
declare const process: { env: { NODE_ENV?: string } };

export class RevokeGPTLoadError extends Error {
  override name = 'RevokeGPTLoadError';
}

interface Memo {
  origin: string;
  hl: Locale | undefined;
  promise: Promise<RevokeGPTApi>;
}

function allowLocalhost(): boolean {
  try {
    return process.env.NODE_ENV !== 'production';
  } catch {
    return false;
  }
}

/** The exact origin, or a RevokeGPTLoadError. Only a bare `https:` origin is accepted. */
export function pinOrigin(origin: string): string {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    throw new RevokeGPTLoadError('origin is not a URL');
  }
  const bare = url.username === '' && url.password === '' && url.search === '' && url.hash === '';
  const rootOnly = url.pathname === '/' && (origin === url.origin || origin === `${url.origin}/`);
  if (!bare || !rootOnly) throw new RevokeGPTLoadError('origin must be an origin, with no path');
  if (url.protocol === 'https:') return url.origin;
  if (url.protocol === 'http:' && url.hostname === 'localhost' && allowLocalhost()) {
    return url.origin;
  }
  throw new RevokeGPTLoadError('origin must be https');
}

function memo(): Memo | undefined {
  return (globalThis as Record<symbol, Memo | undefined>)[LOAD_KEY];
}

/** The loaded API: set by `load()` or already defined by a page that included the script. */
export function loadedApi(): RevokeGPTApi | undefined {
  const api = (globalThis as { revokegpt?: unknown }).revokegpt;
  if (api === undefined) return undefined;
  const shaped =
    typeof api === 'object' &&
    api !== null &&
    ['render', 'execute', 'reset', 'getResponse', 'ready', 'remove'].every(
      (name) => typeof (api as Record<string, unknown>)[name] === 'function',
    );
  if (!shaped) {
    throw new RevokeGPTLoadError('window.revokegpt is not the RevokeGPT loader');
  }
  return api as RevokeGPTApi;
}

/** The `hl` given to the load that is (or was) in effect. */
export function defaultHl(): Locale | undefined {
  return memo()?.hl;
}

function whenReady(): Promise<RevokeGPTApi> {
  let api: RevokeGPTApi | undefined;
  try {
    api = loadedApi();
  } catch (error) {
    return Promise.reject(error);
  }
  if (api === undefined) {
    return Promise.reject(new RevokeGPTLoadError('the script loaded but defined no revokegpt'));
  }
  return new Promise((resolve) => api.ready(() => resolve(api)));
}

function inject(origin: string, nonce: string | undefined): Promise<RevokeGPTApi> {
  const src = `${origin}${SCRIPT_PATH}`;
  return new Promise<RevokeGPTApi>((resolve, reject) => {
    if (typeof document === 'undefined') {
      reject(new RevokeGPTLoadError('load() needs a browser document'));
      return;
    }
    let script: HTMLScriptElement | undefined;
    for (const s of Array.from(document.getElementsByTagName('script'))) {
      if (s.src === src) script = s; // the page already has the loader tag
    }
    const owned = script === undefined;
    let existing: RevokeGPTApi | undefined;
    try {
      existing = loadedApi();
    } catch (error) {
      reject(error);
      return;
    }
    if (existing !== undefined) {
      // A loader that is already defined is reused only when its script tag is the pinned
      // origin's: the global alone does not say where it came from.
      if (script === undefined) {
        reject(new RevokeGPTLoadError(`window.revokegpt was not loaded from ${origin}`));
        return;
      }
      whenReady().then(resolve, reject);
      return;
    }
    const el = script ?? document.createElement('script');
    let done = false;
    const finish = (fn: () => void) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      el.removeEventListener('load', onLoad);
      el.removeEventListener('error', onError);
      fn();
    };
    const fail = (message: string) =>
      finish(() => {
        if (owned) el.remove();
        reject(new RevokeGPTLoadError(message));
      });
    const onLoad = () => finish(() => whenReady().then(resolve, reject));
    const onError = () => fail('the RevokeGPT script failed to load');
    const timer = setTimeout(() => fail('the RevokeGPT script timed out'), LOAD_TIMEOUT_MS);
    el.addEventListener('load', onLoad);
    el.addEventListener('error', onError);
    if (owned) {
      el.src = src;
      el.async = true;
      el.defer = true;
      if (nonce !== undefined && nonce !== '') {
        el.nonce = nonce;
        el.setAttribute('nonce', nonce);
      }
      document.head.appendChild(el);
    }
  });
}

/**
 * Loads the RevokeGPT script once and resolves with the loader API when its `ready` fires.
 * Memoised on `globalThis[Symbol.for('revokegpt.load')]`; a failed load is forgotten so a
 * later call can retry.
 */
export function load(opts: LoadOptions = {}): Promise<RevokeGPTApi> {
  let origin: string;
  try {
    if (opts.hl !== undefined && !LOCALES.has(opts.hl)) {
      throw new RevokeGPTLoadError('hl is not a launch locale');
    }
    origin = pinOrigin(opts.origin ?? DEFAULT_ORIGIN);
  } catch (error) {
    return Promise.reject(error);
  }
  const held = memo();
  if (held !== undefined) {
    if (held.origin !== origin) {
      return Promise.reject(
        new RevokeGPTLoadError(`already loading from ${held.origin}, not ${origin}`),
      );
    }
    return held.promise;
  }
  const promise = inject(origin, opts.nonce);
  const entry: Memo = { origin, hl: opts.hl, promise };
  (globalThis as Record<symbol, Memo | undefined>)[LOAD_KEY] = entry;
  promise.catch(() => {
    if (memo() === entry) (globalThis as Record<symbol, Memo | undefined>)[LOAD_KEY] = undefined;
  });
  return promise;
}
