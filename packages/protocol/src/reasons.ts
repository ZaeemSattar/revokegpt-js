/**
 * Reason codes. The array index IS the bit position in the encoded bitmap.
 * APPEND-ONLY FOREVER: never reorder, remove or insert; only add to the end.
 */
export const REASON_CODES = Object.freeze([
  'AUTOMATION', // bit 0
  'UNEXPECTED_ENVIRONMENT', // bit 1
  'TOO_MUCH_TRAFFIC', // bit 2
  'UNEXPECTED_USAGE_PATTERNS', // bit 3
  'DATACENTER_IP', // bit 4
  'ANONYMIZER', // bit 5
  'INTEGRITY_FAILED', // bit 6
  'LOW_CONFIDENCE_SCORE', // bit 7
  'NETWORK_MISMATCH', // bit 8
  'PLAN_RESTRICTED', // bit 9
] as const);

export type ReasonCode = (typeof REASON_CODES)[number];

export function encodeReasons(reasons: readonly ReasonCode[]): number {
  let bits = 0;
  for (const reason of reasons) {
    const index = REASON_CODES.indexOf(reason);
    if (index === -1) throw new RangeError(`unknown reason code: ${String(reason)}`);
    bits |= 1 << index;
  }
  return bits;
}

/** Unknown (future) bits are ignored so older readers tolerate newer writers. */
export function decodeReasons(bits: number): ReasonCode[] {
  if (!Number.isInteger(bits) || bits < 0 || bits >= 2 ** 31) {
    throw new RangeError('reason bitmap must be an integer in [0, 2^31)');
  }
  return REASON_CODES.filter((_, index) => (bits & (1 << index)) !== 0);
}
