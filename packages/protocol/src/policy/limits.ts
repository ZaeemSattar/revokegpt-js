/**
 * Firewall policy limits (protocol v1, section 18). The single source: every port repeats these
 * numbers and the vectors in `test-vectors/policy.json` pin them.
 */
export const POLICY_LIMITS = Object.freeze({
  /** Policies (rules) per site. */
  maxPolicies: 100,
  /** Actions per rule; at most one of them is terminal. */
  maxActionsPerRule: 8,
  /** Characters in a path glob. */
  maxGlobLength: 200,
  /** Wildcards (`*` and `**`) in a path glob. */
  maxWildcards: 8,
  /** Host patterns per rule. */
  maxHostsPerRule: 16,
  /** Methods per rule. */
  maxMethodsPerRule: 8,
  /** Host patterns per site (the bundle `hosts` list). */
  maxSiteHosts: 64,
  /** Decoded bundle payload bytes (64 KiB). */
  maxBundleBytes: 65536,
  /** Served bundle JSON characters (the payload is base64url, so 4/3 larger, plus the envelope). */
  maxServedBytes: 98304,
  /** Bytes of the raw request path (without the query); over this the path is non-canonical. */
  maxRawPathBytes: 8192,
  /** Entries in `revokedJti`. */
  maxRevokedJti: 1000,
  /** Characters in a `setHeader` value (printable ASCII, no CR or LF). */
  maxSetHeaderValue: 256,
  /** Characters in a `setHeader` name. */
  maxSetHeaderName: 64,
  /** Characters in a rule name. */
  maxRuleName: 64,
  /** Bytes in any of the three cookies. */
  maxCookieBytes: 4096,
  /** Characters in a session token. */
  maxSessionTokenLength: 4096,
  /** Bundle validity (seconds). */
  bundleValiditySeconds: 86400,
  /** Stale-while-error grace after `expiresAt` (seconds); after it the fail mode applies. */
  staleGraceSeconds: 21600,
  /** Accepted clock skew (seconds). */
  clockSkewSeconds: 300,
  /** Longest `ret` cookie (return path) in characters. */
  maxReturnPathLength: 2048,
});

/** Signature algorithms a bundle or session token may use. Task 0 outcome: Ed25519 only. */
export const POLICY_ALGS = Object.freeze(['Ed25519'] as const);
export type PolicyAlg = (typeof POLICY_ALGS)[number];

/** Domain prefix of the bundle signature: utf8("rg-policy-v1") followed by one NUL byte. */
export const POLICY_SIGNATURE_DOMAIN = 'rg-policy-v1\u0000';
/** Domain prefix of the session token signature: utf8("rg-session-v1") followed by one NUL byte. */
export const SESSION_SIGNATURE_DOMAIN = 'rg-session-v1\u0000';

/** Cookie names and attributes (section 18). */
export const POLICY_COOKIES = Object.freeze({
  session: '__Host-rg_s',
  clearance: '__Host-rg_c',
  returnPath: '__Host-rg_r',
  attributes: 'HttpOnly; Secure; SameSite=Lax; Path=/',
});

/** Paths served by the integration itself, before any policy is evaluated. */
export const POLICY_RESERVED_PATHS = Object.freeze({
  return: '/__rg/return',
  session: '/__rg/session',
  /** Body limit of the `/__rg/return` urlencoded POST (field `rg_clearance`). */
  returnBodyLimit: 4096,
  returnField: 'rg_clearance',
  sessionInitHeader: 'X-RG-Session-Init',
});
