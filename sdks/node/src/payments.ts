import { containsPanRun, TransactionData } from '@revokegpt/protocol';
import { RevokeGPTError } from './assessments.js';

/** The payment details of an assessment (protocol v1 section 20). */
export type TransactionDataInput = TransactionData;

const BIN = /^(\d{6}|\d{8})$/;
const LAST4 = /^\d{4}$/;
const PAN_MESSAGE = 'a card number must never be sent';

/**
 * Throws `RevokeGPTError('bad-request', 0)` when `s` holds a card number. Status 0 means no request
 * was made: a card number never leaves the process.
 */
export function scanForPan(s: string): void {
  if (containsPanRun(s)) throw new RevokeGPTError('bad-request', 0);
}

/**
 * The card fields of `transactionData` from a BIN (first 6 or 8 digits) and the last four digits.
 * Validated locally, so a card number can never be sent by mistake: anything that is not 6 or 8
 * digits and 4 digits throws `RevokeGPTError('bad-request', 0)` (no request was made). The message
 * never includes the value.
 */
export function cardFields(i: { bin?: string; last4?: string }): {
  cardBin?: string;
  cardLastFour?: string;
} {
  if (typeof i !== 'object' || i === null) throw new TypeError('invalid card fields');
  const out: { cardBin?: string; cardLastFour?: string } = {};
  if (i.bin !== undefined) {
    if (typeof i.bin !== 'string' || !BIN.test(i.bin)) throw new RevokeGPTError('bad-request', 0);
    out.cardBin = i.bin;
  }
  if (i.last4 !== undefined) {
    if (typeof i.last4 !== 'string' || !LAST4.test(i.last4))
      throw new RevokeGPTError('bad-request', 0);
    out.cardLastFour = i.last4;
  }
  return out;
}

/**
 * Validates `transactionData` against the protocol schema before sending. A string that holds a
 * card number (anywhere, including `items[].name`) is `RevokeGPTError('bad-request', 0)`; any
 * other violation is a `TypeError` that never includes the value.
 */
export function checkTransactionData(value: unknown): TransactionDataInput {
  if (typeof value !== 'object' || value === null || Array.isArray(value))
    throw new TypeError('invalid transactionData');
  const r = TransactionData.safeParse(value);
  if (r.success) return r.data;
  if (r.error.issues.some((x) => x.message === PAN_MESSAGE))
    throw new RevokeGPTError('bad-request', 0);
  throw new TypeError('invalid transactionData');
}
