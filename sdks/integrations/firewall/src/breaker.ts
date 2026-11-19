/**
 * Circuit breaker for siteverify: opens after `threshold` consecutive failures and stays open for
 * `openMs`, during which `allow()` is false and the caller applies `onError` without any call.
 * After that it closes with one failure of headroom left, so a single further failure reopens it.
 */
export class Breaker {
  readonly #threshold: number;
  readonly #openMs: number;
  readonly #now: () => number;
  #failures = 0;
  #openUntil = 0;

  constructor(threshold = 5, openMs = 30_000, now: () => number = Date.now) {
    this.#threshold = threshold;
    this.#openMs = openMs;
    this.#now = now;
  }

  allow(): boolean {
    if (this.#openUntil === 0) return true;
    if (this.#now() < this.#openUntil) return false;
    this.#openUntil = 0;
    this.#failures = this.#threshold - 1;
    return true;
  }

  success(): void {
    this.#failures = 0;
    this.#openUntil = 0;
  }

  failure(): void {
    this.#failures++;
    if (this.#failures >= this.#threshold) this.#openUntil = this.#now() + this.#openMs;
  }
}
