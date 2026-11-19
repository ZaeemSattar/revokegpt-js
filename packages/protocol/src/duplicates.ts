/**
 * Duplicate-key detection for request bodies (protocol v1 section 10, "Request parsing"). Standard
 * parsers silently keep one of two duplicate keys (`JSON.parse` and Hono's `parseBody` the last,
 * others the first), so a body with a duplicate is read one way by one component and another way
 * by the next. The server rejects any duplicate instead; neither first-wins nor last-wins is
 * acceptable. Enforcement in the server is planned (M1); this is the reference check.
 */

/** Longest body (in UTF-16 code units) the scan accepts: the largest body limit, 64 KiB. */
export const DUPLICATE_SCAN_MAX_LENGTH = 65536;

/**
 * True if `raw` has a duplicate key, or cannot be shown not to have one (fail closed): `raw` is not
 * a string, is longer than `DUPLICATE_SCAN_MAX_LENGTH`, is not well-formed JSON (for `'json'`), or
 * `contentType` is neither `'json'` nor `'form'`. Never throws; work is linear in the length.
 *
 * - `'json'`: an RFC 8259 scan, without recursion, that compares keys after unescaping, within each
 *   object at any depth (so `"secret"` and `"secret"` are the same key, and so are two
 *   `"__proto__"` keys). It accepts exactly the JSON text that `JSON.parse` accepts.
 * - `'form'`: `application/x-www-form-urlencoded`, decoded with `URLSearchParams`. A key is compared
 *   by its name up to the first `[`, so `a`, `a[]` and `a[x]` all count as `a` (parsers such as
 *   PHP's and `qs` turn them into one array or object).
 */
export function hasDuplicateKeys(raw: string, contentType: 'json' | 'form'): boolean {
  try {
    if (typeof raw !== 'string' || raw.length > DUPLICATE_SCAN_MAX_LENGTH) return true;
    if (contentType === 'json') return jsonHasDuplicateKeys(raw);
    if (contentType === 'form') return formHasDuplicateKeys(raw);
    return true;
  } catch {
    return true;
  }
}

function formHasDuplicateKeys(raw: string): boolean {
  const seen = new Set<string>();
  for (const key of new URLSearchParams(raw).keys()) {
    const bracket = key.indexOf('[');
    const name = bracket === -1 ? key : key.slice(0, bracket);
    if (seen.has(name)) return true;
    seen.add(name);
  }
  return false;
}

// Scanner states: expecting a value, expecting an object key, or after a complete value.
const VALUE = 0;
const KEY = 1;
const AFTER_VALUE = 2;
const HEX4 = /^[0-9A-Fa-f]{4}$/;

/** True on a duplicate key in any one object, or on input that is not well-formed JSON. */
function jsonHasDuplicateKeys(s: string): boolean {
  const n = s.length;
  let i = 0;
  // One entry per open container: the keys seen so far for an object, null for an array.
  const stack: (Set<string> | null)[] = [];
  let state: number = VALUE;

  const skipWhitespace = () => {
    for (; i < n; i++) {
      const c = s.charCodeAt(i);
      if (c !== 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) return;
    }
  };

  /** Reads the string starting at the `"` at `i`; returns its decoded value, or null if malformed. */
  const readString = (): string | null => {
    i++; // opening quote
    let out = '';
    let start = i;
    for (; i < n; i++) {
      const c = s.charCodeAt(i);
      if (c === 0x22) {
        out += s.slice(start, i);
        i++;
        return out;
      }
      if (c < 0x20) return null;
      if (c !== 0x5c) continue;
      out += s.slice(start, i);
      const e = s.charCodeAt(i + 1);
      if (e === 0x75) {
        const hex = s.slice(i + 2, i + 6);
        if (!HEX4.test(hex)) return null;
        out += String.fromCharCode(Number.parseInt(hex, 16));
        i += 5;
      } else {
        const simple = ESCAPES[e];
        if (simple === undefined) return null;
        out += simple;
        i += 1;
      }
      start = i + 1;
    }
    return null; // unterminated
  };

  /** Skips a number at `i`; false if it is not an RFC 8259 number. */
  const skipNumber = (): boolean => {
    if (s.charCodeAt(i) === 0x2d) i++;
    const first = s.charCodeAt(i);
    if (first === 0x30) i++;
    else if (first >= 0x31 && first <= 0x39) while (isDigit(s.charCodeAt(i))) i++;
    else return false;
    if (s.charCodeAt(i) === 0x2e) {
      i++;
      if (!isDigit(s.charCodeAt(i))) return false;
      while (isDigit(s.charCodeAt(i))) i++;
    }
    const e = s.charCodeAt(i);
    if (e === 0x65 || e === 0x45) {
      i++;
      const sign = s.charCodeAt(i);
      if (sign === 0x2b || sign === 0x2d) i++;
      if (!isDigit(s.charCodeAt(i))) return false;
      while (isDigit(s.charCodeAt(i))) i++;
    }
    return true;
  };

  for (;;) {
    skipWhitespace();
    if (state === VALUE) {
      const c = s.charCodeAt(i);
      if (c === 0x7b) {
        i++;
        skipWhitespace();
        if (s.charCodeAt(i) === 0x7d) {
          i++;
          state = AFTER_VALUE;
        } else {
          stack.push(new Set<string>());
          state = KEY;
        }
      } else if (c === 0x5b) {
        i++;
        skipWhitespace();
        if (s.charCodeAt(i) === 0x5d) {
          i++;
          state = AFTER_VALUE;
        } else {
          stack.push(null);
        }
      } else if (c === 0x22) {
        if (readString() === null) return true;
        state = AFTER_VALUE;
      } else if (c === 0x74 || c === 0x66 || c === 0x6e) {
        const word = c === 0x74 ? 'true' : c === 0x66 ? 'false' : 'null';
        if (s.slice(i, i + word.length) !== word) return true;
        i += word.length;
        state = AFTER_VALUE;
      } else if (c === 0x2d || isDigit(c)) {
        if (!skipNumber()) return true;
        state = AFTER_VALUE;
      } else {
        return true;
      }
    } else if (state === KEY) {
      if (s.charCodeAt(i) !== 0x22) return true;
      const key = readString();
      if (key === null) return true;
      const keys = stack[stack.length - 1];
      if (!keys) return true; // unreachable: KEY is entered only inside an object
      if (keys.has(key)) return true;
      keys.add(key);
      skipWhitespace();
      if (s.charCodeAt(i) !== 0x3a) return true;
      i++;
      state = VALUE;
    } else {
      if (stack.length === 0) return i !== n; // one value, then only whitespace
      const top = stack[stack.length - 1];
      const c = s.charCodeAt(i);
      if (c === 0x2c) {
        i++;
        state = top ? KEY : VALUE;
      } else if ((c === 0x7d && top) || (c === 0x5d && top === null)) {
        i++;
        stack.pop();
      } else {
        return true;
      }
    }
  }
}

function isDigit(c: number): boolean {
  return c >= 0x30 && c <= 0x39;
}

/** Single-character JSON escapes, by the char code after the backslash. */
const ESCAPES: readonly (string | undefined)[] = (() => {
  const t: (string | undefined)[] = new Array(128).fill(undefined);
  t[0x22] = '"';
  t[0x5c] = '\\';
  t[0x2f] = '/';
  t[0x62] = '\b';
  t[0x66] = '\f';
  t[0x6e] = '\n';
  t[0x72] = '\r';
  t[0x74] = '\t';
  return t;
})();
