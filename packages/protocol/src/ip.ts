/**
 * Canonical text of an IP address (protocol v1 section 10, `remoteip`). One address has many
 * accepted spellings (192.0.2.1 alone has 14 that `/v1/siteverify` accepts), so the server
 * canonicalizes `remoteip` before any use: velocity, binding or logging.
 */

/** Longest text `canonicalizeIp` accepts (an IPv6 address with 4-digit groups and an IPv4 tail). */
export const IP_MAX_LENGTH = 45;

const OCTET = /^(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/;
const HEX_GROUP = /^[0-9A-Fa-f]{1,4}$/;
const IPV6_CHARS = /^[0-9A-Fa-f:.]+$/;

/** Four octets from strict dotted decimal (no leading zeros, no other forms), or null. */
function parseIpv4(s: string): number[] | null {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  const out: number[] = [];
  for (const p of parts) {
    if (!OCTET.test(p)) return null;
    out.push(Number(p));
  }
  return out;
}

/** Hex groups separated by single colons (`''` gives none), or null. */
function parseGroups(s: string): number[] | null {
  if (s === '') return [];
  const out: number[] = [];
  for (const g of s.split(':')) {
    if (!HEX_GROUP.test(g)) return null;
    out.push(Number.parseInt(g, 16));
  }
  return out;
}

/**
 * Eight 16-bit groups, or null. Accepts the addresses the `remoteip` schema accepts: hex groups of
 * 1 to 4 digits, at most one `::` standing for one or more zero groups, and an optional dotted-quad
 * tail (strict octets) counting as two groups. No zone id, brackets or whitespace.
 */
function parseIpv6(s: string): number[] | null {
  if (!IPV6_CHARS.test(s)) return null;
  let head = s;
  let tail: number[] = [];
  if (s.includes('.')) {
    const colon = s.lastIndexOf(':');
    if (colon === -1) return null;
    const v4 = parseIpv4(s.slice(colon + 1));
    if (!v4) return null;
    tail = [
      ((v4[0] as number) << 8) | (v4[1] as number),
      ((v4[2] as number) << 8) | (v4[3] as number),
    ];
    head = s.slice(0, colon + 1);
    // Keep a trailing `::`; drop the single `:` that separated the groups from the tail.
    if (!head.endsWith('::')) head = head.slice(0, -1);
  }
  const halves = head.split('::');
  if (halves.length > 2) return null;
  if (halves.length === 2) {
    const left = parseGroups(halves[0] as string);
    const right = parseGroups(halves[1] as string);
    if (!left || !right) return null;
    const explicit = left.length + right.length + tail.length;
    if (explicit > 7) return null;
    return [...left, ...new Array<number>(8 - explicit).fill(0), ...right, ...tail];
  }
  const groups = parseGroups(head);
  if (!groups || groups.length + tail.length !== 8) return null;
  return [...groups, ...tail];
}

/** RFC 5952 text: lowercase, no leading zeros, the longest run of 2+ zero groups as `::` (first on a tie). */
function formatIpv6(g: number[]): string {
  let bestStart = -1;
  let bestLen = 1;
  for (let i = 0; i < 8; ) {
    if (g[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = (xs: number[]) => xs.map((x) => x.toString(16)).join(':');
  if (bestStart === -1) return hex(g);
  return `${hex(g.slice(0, bestStart))}::${hex(g.slice(bestStart + bestLen))}`;
}

/**
 * The canonical text of an IPv4 or IPv6 address, or null if `s` is not one (exactly the addresses
 * the `/v1/siteverify` `remoteip` schema accepts). IPv4: dotted decimal, already canonical when
 * accepted. IPv6: RFC 5952 (lowercase hex, no leading zeros, the longest run of two or more zero
 * groups compressed to `::`, the first on a tie, a single zero group never compressed, no dotted
 * tail); an IPv4-mapped address (`::ffff:0:0/96`) becomes its IPv4 dotted quad, so
 * `::ffff:192.0.2.1` and `::FFFF:c000:0201` both give `192.0.2.1`. Other embedded-IPv4 forms
 * (`::192.0.2.1`, `64:ff9b::192.0.2.1`) are different addresses and stay IPv6. Input longer than
 * `IP_MAX_LENGTH` (45) is null before parsing. Never throws.
 */
export function canonicalizeIp(s: string): string | null {
  // The longest accepted text is 45 characters (`0000:0000:0000:0000:0000:ffff:255.255.255.255`);
  // anything longer is rejected before any parsing.
  if (typeof s !== 'string' || s.length > IP_MAX_LENGTH) return null;
  if (!s.includes(':')) {
    const v4 = parseIpv4(s);
    return v4 ? v4.join('.') : null;
  }
  const g = parseIpv6(s);
  if (!g) return null;
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff) {
    const hi = g[6] as number;
    const lo = g[7] as number;
    return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
  }
  return formatIpv6(g);
}
