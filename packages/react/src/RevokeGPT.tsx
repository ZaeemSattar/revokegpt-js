'use client';
import {
  type Badge,
  type Locale,
  load,
  render,
  type Size,
  type Theme,
  type Widget,
} from '@revokegpt/js';
import { forwardRef, type HTMLAttributes, useEffect, useImperativeHandle, useRef } from 'react';

/** Props of the host `<div>` that the component passes through (`id`, `style`, `data-*`, `aria-*`, `title`, ...). */
type HostProps = Omit<
  HTMLAttributes<HTMLDivElement>,
  'children' | 'onError' | 'dangerouslySetInnerHTML'
>;

export interface RevokeGPTProps extends HostProps {
  /** The site key (`rgpk_` plus 20 letters or digits). */
  sitekey: string;
  theme?: Theme;
  /** Default `invisible`. */
  size?: Size;
  hl?: Locale;
  action?: string;
  cdata?: string;
  tabIndex?: number;
  badge?: Badge;
  /** A widget origin, validated by `@revokegpt/js` (`https:` only). There is no script-URL prop. */
  origin?: string;
  /** Copied onto the injected script as its CSP nonce. */
  nonce?: string;
  /** Receives the response token. Read through a ref: changing it never re-renders the widget. */
  onVerify?: (token: string) => void;
  onExpire?: () => void;
  /** Receives the error code (`network-error`, or `load-error` when the script did not load). */
  onError?: (code: string) => void;
}

export interface RevokeGPTHandle {
  execute(): Promise<string>;
  reset(): void;
  getResponse(): string;
}

export const RevokeGPT = forwardRef<RevokeGPTHandle, RevokeGPTProps>(function RevokeGPT(
  {
    sitekey,
    theme,
    size,
    hl,
    action,
    cdata,
    tabIndex,
    badge,
    origin,
    nonce,
    onVerify,
    onExpire,
    onError,
    ...hostProps
  },
  ref,
) {
  const host = useRef<HTMLDivElement>(null);
  const widget = useRef<Widget | null>(null);
  const cbs = { onVerify, onExpire, onError };
  const callbacks = useRef(cbs);
  // Declared before the widget effect so the latest callbacks are in place first.
  useEffect(() => {
    callbacks.current = cbs;
  });

  useImperativeHandle(
    ref,
    () => ({
      execute: () => widget.current?.execute() ?? Promise.reject(new Error('widget is not ready')),
      reset: () => widget.current?.reset(),
      getResponse: () => widget.current?.getResponse() ?? '',
    }),
    [],
  );

  // Props that need a new widget (sitekey, size, theme, hl, ...) are the dependencies: a change
  // destroys the old widget and renders a new one. A mount that is cleaned up before load()
  // resolves creates nothing (StrictMode mount, unmount, mount leaves exactly one widget).
  useEffect(() => {
    const el = host.current;
    if (el === null) return;
    let live = true;
    let mine: Widget | undefined;
    load({
      ...(origin !== undefined && { origin }),
      ...(nonce !== undefined && { nonce }),
      ...(hl !== undefined && { hl }),
    }).then(
      () => {
        if (!live) return;
        try {
          mine = render(el, {
            sitekey,
            ...(theme !== undefined && { theme }),
            ...(size !== undefined && { size }),
            ...(hl !== undefined && { hl }),
            ...(action !== undefined && { action }),
            ...(cdata !== undefined && { cdata }),
            ...(tabIndex !== undefined && { tabindex: tabIndex }),
            ...(badge !== undefined && { badge }),
            callback: (token) => callbacks.current.onVerify?.(token),
            'expired-callback': () => callbacks.current.onExpire?.(),
            'error-callback': (code) => callbacks.current.onError?.(code),
          });
          widget.current = mine;
        } catch {
          callbacks.current.onError?.('render-error');
        }
      },
      () => {
        if (live) callbacks.current.onError?.('load-error');
      },
    );
    return () => {
      live = false;
      mine?.destroy();
      if (widget.current === mine) widget.current = null;
    };
  }, [sitekey, theme, size, hl, action, cdata, tabIndex, badge, origin, nonce]);

  // `tabIndex` is the widget's own prop (the frame's tab order), not the host div's. The host's
  // content is the widget's own: a `children` a JS caller passes anyway is dropped.
  const { children: _children, ...divProps } = hostProps as HTMLAttributes<HTMLDivElement>;
  return <div {...divProps} ref={host} />;
});
