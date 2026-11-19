/**
 * `@revokegpt/js`: a typed wrapper over the RevokeGPT browser loader (`window.revokegpt`).
 *
 *   const api = await load({ nonce });
 *   const widget = render(el, { sitekey, action: 'login' });
 *   const token = await widget.execute();
 */
import { defaultHl, loadedApi, RevokeGPTLoadError } from './load.js';
import type { ChallengeAccountOptions, RenderOptions, Widget } from './types.js';

export { DEFAULT_ORIGIN, load, RevokeGPTLoadError } from './load.js';
export type {
  Badge,
  ChallengeAccountOptions,
  LoadOptions,
  Locale,
  RenderOptions,
  RevokeGPTApi,
  Size,
  Theme,
  Widget,
} from './types.js';

/**
 * Renders a widget into `el`. Call it after `await load()`. `destroy()` removes the widget and is
 * idempotent; the other methods then do nothing (`execute` rejects, `getResponse` gives '').
 */
export function render(el: Element, opts: RenderOptions): Widget {
  const api = loadedApi(); // throws if the global is not the loader
  if (api === undefined) {
    throw new RevokeGPTLoadError('render() needs the script: await load() first');
  }
  const hl = opts.hl ?? defaultHl();
  const id = api.render(el, hl === undefined ? opts : { ...opts, hl });
  let destroyed = false;
  return {
    id,
    execute() {
      if (destroyed) return Promise.reject(new Error('widget was destroyed'));
      return api.execute(id);
    },
    reset() {
      if (!destroyed) api.reset(id);
    },
    getResponse() {
      return destroyed ? '' : api.getResponse(id);
    },
    destroy() {
      if (destroyed) return;
      destroyed = true;
      api.remove(id);
    },
  };
}

/**
 * Account verification (email code, protocol v1 section 17). Call it after `await load()`, with
 * the `requestToken` of an assessment's `accountVerification.endpoints` entry. A dialog asks the
 * person for the code the service emailed; the promise resolves with the verification token, which
 * your server presents in a following assessment of the same account (success or failure is read
 * there, not here), and rejects with `Error('cancelled')` when the person cancels. Only one dialog
 * is open at a time: a call while one is open rejects at once with `Error('busy')` (its `code` is
 * `'busy'`) and leaves the open dialog alone.
 */
export function challengeAccount(sitekey: string, opts: ChallengeAccountOptions): Promise<string> {
  let api: ReturnType<typeof loadedApi>;
  try {
    api = loadedApi();
  } catch (error) {
    return Promise.reject(error);
  }
  if (api === undefined) {
    return Promise.reject(
      new RevokeGPTLoadError('challengeAccount() needs the script: await load() first'),
    );
  }
  if (typeof api.challengeAccount !== 'function') {
    return Promise.reject(
      new RevokeGPTLoadError('this loader release has no challengeAccount; load a newer one'),
    );
  }
  const languageCode = opts.languageCode ?? defaultHl();
  return api.challengeAccount(
    sitekey,
    languageCode === undefined ? opts : { ...opts, languageCode },
  );
}
