// Internal helpers (not part of the package's exports map).

/**
 * Settles with `p`, or rejects with `signal.reason` as soon as `signal` aborts, even if `p` ignores
 * the signal. `p` is always handled: when the abort wins (or `signal` is already aborted), a later
 * rejection of `p` is swallowed and a later value is passed to `onLate` (to release it, for example
 * to cancel a response body nobody will read). `onLate` never throws out.
 */
export function abortable<T>(
  p: Promise<T>,
  signal: AbortSignal,
  onLate?: (value: T) => void,
): Promise<T> {
  const late = (value: T) => {
    try {
      onLate?.(value);
    } catch {
      // Releasing a late value is best effort.
    }
  };
  if (signal.aborted) {
    p.then(late, () => {});
    return Promise.reject(signal.reason);
  }
  return new Promise<T>((resolve, reject) => {
    let aborted = false;
    const onAbort = () => {
      aborted = true;
      reject(signal.reason);
    };
    signal.addEventListener('abort', onAbort, { once: true });
    p.then(
      (v) => {
        signal.removeEventListener('abort', onAbort);
        if (aborted) late(v);
        else resolve(v);
      },
      (e: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(e); // A no-op when the abort already rejected.
      },
    );
  });
}

/** Cancels a reader or stream without waiting and without letting it throw. */
export function discard(x: unknown): void {
  try {
    const p = (x as { cancel?: () => unknown } | null | undefined)?.cancel?.();
    if (p instanceof Promise) p.catch(() => {});
  } catch {
    // Nothing to release.
  }
}
