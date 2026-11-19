/** The longest username the canonicalization accepts, in UTF-16 code units, before normalization. */
export const USERNAME_MAX_LENGTH = 512;

/**
 * The canonical username (protocol v1 section 15): NFKC, trim, lowercase. When the result has
 * exactly one `@`, a `+tag` is dropped from the local part (from the first `+` to the `@`), unless
 * that would leave it empty.
 */
export function canonicalUsername(u: string): string {
  if (typeof u !== 'string') throw new TypeError('username must be a string');
  if (u.length > USERNAME_MAX_LENGTH) throw new RangeError('username is too long');
  const s = u.normalize('NFKC').trim().toLowerCase();
  const at = s.indexOf('@');
  if (at < 0 || s.indexOf('@', at + 1) >= 0) return s;
  const plus = s.indexOf('+');
  return plus > 0 && plus < at ? s.slice(0, plus) + s.slice(at) : s;
}
