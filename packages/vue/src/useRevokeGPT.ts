import { type Badge, type Locale, load, render, type Theme, type Widget } from '@revokegpt/js';
import {
  getCurrentInstance,
  type MaybeRefOrGetter,
  onBeforeUnmount,
  onMounted,
  type Ref,
  ref,
  toValue,
  watch,
} from 'vue';

export interface UseRevokeGPTOptions {
  sitekey: string;
  /** The default action; `execute(action)` overrides it per call. */
  action?: string;
  cdata?: string;
  hl?: Locale;
  theme?: Theme;
  badge?: Badge;
  origin?: string;
  nonce?: string;
}

export interface UseRevokeGPTResult {
  /** Runs the challenge and resolves with the token. Waits for the widget; rejects after unmount. */
  execute(action?: string): Promise<string>;
  /** True once the script is loaded and the invisible widget exists. */
  ready: Readonly<Ref<boolean>>;
}

declare const process: { env?: { NODE_ENV?: string } } | undefined;
const isProduction = (): boolean =>
  typeof process !== 'undefined' && process?.env?.NODE_ENV === 'production';

/**
 * An invisible widget without markup of your own: call `execute()` where you need a token. Call it
 * in `setup()`. `opts` may be a ref or a getter; a change (except of `action`, read at each request) recreates the widget, as in React.
 */
export function useRevokeGPT(opts: MaybeRefOrGetter<UseRevokeGPTOptions>): UseRevokeGPTResult {
  // Outside setup() no lifecycle hook is registered, so the widget would never be created or
  // destroyed: in development say so loudly instead of leaving a silent Vue warning.
  if (getCurrentInstance() === null && !isProduction()) {
    throw new Error(
      'useRevokeGPT() must be called inside setup() (or another component lifecycle).',
    );
  }
  const ready = ref(false);
  let run: ((a?: string) => Promise<string>) | undefined;
  let stop: (() => void) | undefined;

  function start(): void {
    const o = toValue(opts);
    let live = true;
    let widget: Widget | undefined;
    let current = o.action;
    ready.value = false;
    // Read at the start of each request, so a changed default action never destroys a widget that
    // is in the middle of one.
    const latestAction = () => toValue(opts).action;
    const host = document.createElement('div');
    document.body.appendChild(host);
    const make = (a: string | undefined): Widget =>
      render(host, {
        sitekey: o.sitekey,
        size: 'invisible',
        ...(a !== undefined && { action: a }),
        ...(o.cdata !== undefined && { cdata: o.cdata }),
        ...(o.hl !== undefined && { hl: o.hl }),
        ...(o.theme !== undefined && { theme: o.theme }),
        ...(o.badge !== undefined && { badge: o.badge }),
      });
    const loaded = load({
      ...(o.origin !== undefined && { origin: o.origin }),
      ...(o.nonce !== undefined && { nonce: o.nonce }),
      ...(o.hl !== undefined && { hl: o.hl }),
    }).then(() => {
      if (!live) throw new Error('unmounted');
      widget = make(current);
      ready.value = true;
    });
    loaded.catch(() => {}); // surfaced to callers of execute()
    // One execute at a time: a call with a different action waits for the in-flight one.
    let chain: Promise<unknown> = Promise.resolve();
    const step = async (a: string | undefined): Promise<string> => {
      await loaded;
      if (!live || widget === undefined) throw new Error('unmounted');
      const want = a ?? latestAction();
      if (want !== current) {
        widget.destroy();
        current = want;
        widget = make(want);
      }
      return widget.execute();
    };
    run = (a) => {
      const result = chain.then(() => step(a));
      chain = result.catch(() => {});
      return result;
    };
    stop = () => {
      live = false;
      widget?.destroy();
      host.remove();
      run = undefined;
      stop = undefined;
    };
  }

  onMounted(() => {
    start();
    watch(
      () => {
        const o = toValue(opts);
        // One string, not an array: a getter that spreads `opts` also tracks `action`, and a new array
        // is "changed" on every trigger, so the key is compared by value.
        return JSON.stringify([o.sitekey, o.cdata, o.hl, o.theme, o.badge, o.origin, o.nonce]);
      },
      () => {
        stop?.();
        start();
      },
    );
  });
  onBeforeUnmount(() => stop?.());

  return {
    execute: (a) => run?.(a) ?? Promise.reject(new Error('widget is not ready')),
    ready,
  };
}
