'use client';
import { type Badge, type Locale, load, render, type Theme, type Widget } from '@revokegpt/js';
import { useCallback, useEffect, useRef, useState } from 'react';

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
  ready: boolean;
}

/** An invisible widget without markup of your own: call `execute()` where you need a token. */
export function useRevokeGPT(opts: UseRevokeGPTOptions): UseRevokeGPTResult {
  const { sitekey, action, cdata, hl, theme, badge, origin, nonce } = opts;
  const [ready, setReady] = useState(false);
  const run = useRef<((a?: string) => Promise<string>) | null>(null);
  // The default action is read when a request starts, so changing it never destroys a widget that
  // is in the middle of one (it is not an effect dependency): the next request uses the new one.
  const defaultAction = useRef(action);
  defaultAction.current = action;

  useEffect(() => {
    let live = true;
    let widget: Widget | undefined;
    let current = defaultAction.current;
    const host = document.createElement('div');
    document.body.appendChild(host);
    const make = (a: string | undefined): Widget =>
      render(host, {
        sitekey,
        size: 'invisible',
        ...(a !== undefined && { action: a }),
        ...(cdata !== undefined && { cdata }),
        ...(hl !== undefined && { hl }),
        ...(theme !== undefined && { theme }),
        ...(badge !== undefined && { badge }),
      });
    const loaded = load({
      ...(origin !== undefined && { origin }),
      ...(nonce !== undefined && { nonce }),
      ...(hl !== undefined && { hl }),
    }).then(() => {
      if (!live) throw new Error('unmounted');
      widget = make(current);
      setReady(true);
    });
    loaded.catch(() => {}); // surfaced to callers of execute()
    // One execute at a time: a call with a different action waits for the in-flight one rather
    // than destroying its widget.
    let chain: Promise<unknown> = Promise.resolve();
    const step = async (a: string | undefined): Promise<string> => {
      await loaded;
      if (!live || widget === undefined) throw new Error('unmounted');
      const want = a ?? defaultAction.current;
      if (want !== current) {
        widget.destroy();
        current = want;
        widget = make(want);
      }
      return widget.execute();
    };
    run.current = (a) => {
      const result = chain.then(() => step(a));
      chain = result.catch(() => {});
      return result;
    };
    return () => {
      live = false;
      widget?.destroy();
      host.remove();
      run.current = null;
      // A new widget is on its way (or the component is gone): not ready until it exists.
      setReady(false);
    };
  }, [sitekey, cdata, hl, theme, badge, origin, nonce]);

  const execute = useCallback(
    (a?: string) => run.current?.(a) ?? Promise.reject(new Error('widget is not ready')),
    [],
  );
  return { execute, ready };
}
