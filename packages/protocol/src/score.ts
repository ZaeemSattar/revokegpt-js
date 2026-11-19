/**
 * Clamp to [0, 1] and round to 0.1 steps. Fails closed: any input that is not a primitive number
 * (undefined, null, strings, objects with `valueOf`, arrays, BigInt), NaN, and both infinities
 * give 0, so a missing or malformed score can never pass a `score < threshold` gate. A model that
 * emits +Infinity or -Infinity has a bug; its output is not clamped to 1.
 */
export function quantizeScore(raw: unknown): number {
  if (typeof raw !== 'number' || !Number.isFinite(raw)) return 0;
  const clamped = Math.min(1, Math.max(0, raw));
  return Math.round(clamped * 10) / 10;
}
