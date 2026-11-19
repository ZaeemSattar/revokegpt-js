import { z } from 'zod';
import { canonicalizeHostname, isValidHostnamePattern } from '../hostname.js';
import { ACTION, copyRegex, SITE_ID, SITE_KEY } from '../patterns.js';
import { compileGlob } from './glob.js';
import { POLICY_ALGS, POLICY_LIMITS } from './limits.js';

const BASE62_ID = /^[0-9A-Za-z]{8}$/;
const KID = /^[0-9a-f]{16}$/;
const JTI = /^[A-Za-z0-9_-]{16,32}$/;
const METHOD = /^[A-Z][A-Z-]{0,31}$/;
const HEADER_NAME = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
// Bidi controls and C0/C1 controls are refused in names (they reach MCP output and the dashboard).
// biome-ignore lint/suspicious/noControlCharactersInRegex: that is the point
const NAME_FORBIDDEN = /[\u0000-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/;

/** Header names `setHeader` can never touch (lower case). `x-rg-*` and `x-forwarded-*` are prefixes. */
export const SET_HEADER_DENY: readonly string[] = Object.freeze([
  'host',
  'forwarded',
  'content-length',
  'transfer-encoding',
  'set-cookie',
  'cookie',
  'authorization',
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'trailers',
  'upgrade',
]);

/** True if `name` (any case) is a header `setHeader` may set. */
export function isSettableHeaderName(name: string): boolean {
  if (typeof name !== 'string' || name.length === 0 || name.length > POLICY_LIMITS.maxSetHeaderName)
    return false;
  if (!HEADER_NAME.test(name)) return false;
  if (SET_HEADER_DENY.includes(name)) return false;
  return !(name.startsWith('x-rg-') || name.startsWith('x-forwarded-') || name === 'x-rg');
}

/** True if `v` is a legal `setHeader` value: printable ASCII (0x20-0x7E), at most 256 characters. */
export function isSettableHeaderValue(v: string): boolean {
  return (
    typeof v === 'string' && v.length <= POLICY_LIMITS.maxSetHeaderValue && /^[\x20-\x7e]*$/.test(v)
  );
}

/** A redirect target: a path ("/x", not "//", no backslash, no control) or an https URL on a site host. */
export function isSafeRedirectLocation(loc: string, siteHosts: readonly string[]): boolean {
  if (typeof loc !== 'string' || loc.length === 0 || loc.length > 2048) return false;
  // biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are refused
  if (/[\u0000- \u007f-￿\\]/.test(loc)) return false;
  if (loc.startsWith('/')) return !loc.startsWith('//');
  const m = /^https:\/\/([^/?#:@]+)(?::[0-9]{1,5})?(?:[/?#].*)?$/.exec(loc);
  if (m === null) return false;
  const host = canonicalizeHostname(m[1] as string);
  if (host === null) return false;
  return siteHosts.some((p) => isValidHostnamePattern(p) && patternCovers(p, host));
}

/** True if site pattern `site` matches every host that pattern-or-host `rule` matches. */
export function patternCovers(site: string, rule: string): boolean {
  if (site === rule) return true;
  if (!site.startsWith('*.')) return false;
  const base = site.slice(2);
  const target = rule.startsWith('*.') ? rule.slice(2) : rule;
  return target !== base && target.endsWith(`.${base}`);
}

const HostPattern = z.string().refine(isValidHostnamePattern, { message: 'invalid host pattern' });
const Threshold = z
  .number()
  .min(0.1)
  .max(1)
  .refine((t) => Math.round(t * 10) / 10 === t, { message: 'threshold must be a multiple of 0.1' });

export const PolicyActionSchema = z.discriminatedUnion('type', [
  z.strictObject({ type: z.literal('allow') }),
  z.strictObject({
    type: z.literal('block'),
    status: z.union([z.literal(403), z.literal(404), z.literal(429)]),
  }),
  z.strictObject({
    type: z.literal('requireToken'),
    action: z.string().regex(copyRegex(ACTION)),
    threshold: Threshold,
  }),
  z.strictObject({
    type: z.literal('challengePage'),
    minLevel: z.union([z.literal(1), z.literal(2)]),
  }),
  z.strictObject({
    type: z.literal('redirect'),
    location: z.string().min(1).max(2048),
    status: z.union([z.literal(302), z.literal(307), z.literal(308)]),
  }),
  z.strictObject({ type: z.literal('scoreHeader') }),
  z.strictObject({
    type: z.literal('setHeader'),
    name: z.string().refine(isSettableHeaderName, { message: 'header name not allowed' }),
    value: z.string().refine(isSettableHeaderValue, { message: 'header value not allowed' }),
  }),
]);

export const TERMINAL_ACTIONS = Object.freeze([
  'allow',
  'block',
  'requireToken',
  'challengePage',
  'redirect',
] as const);
const TERMINALS: readonly string[] = TERMINAL_ACTIONS;

/** True if the action ends rule evaluation. */
export function isTerminalAction(a: { type: string }): boolean {
  return TERMINALS.includes(a.type);
}

export const PolicyRuleSchema = z.strictObject({
  id: z.string().regex(BASE62_ID),
  name: z
    .string()
    .min(1)
    .max(POLICY_LIMITS.maxRuleName)
    .refine((n) => !NAME_FORBIDDEN.test(n), { message: 'control or bidi character in name' }),
  enabled: z.boolean(),
  match: z.strictObject({
    hosts: z.array(HostPattern).min(1).max(POLICY_LIMITS.maxHostsPerRule),
    path: z.string().refine((p) => compileGlob(p) !== null, { message: 'invalid path glob' }),
    methods: z
      .array(z.string().regex(METHOD).or(z.literal('*')))
      .min(1)
      .max(POLICY_LIMITS.maxMethodsPerRule)
      .refine((m) => new Set(m).size === m.length, { message: 'duplicate method' })
      .refine((m) => !m.includes('*') || m.length === 1, { message: '* must stand alone' }),
  }),
  when: z
    .strictObject({
      scoreBelow: Threshold.optional(),
      sessionLevelBelow: z.union([z.literal(0), z.literal(1), z.literal(2)]).optional(),
      noSession: z.literal(true).optional(),
    })
    .optional(),
  actions: z
    .array(PolicyActionSchema)
    .min(1)
    .max(POLICY_LIMITS.maxActionsPerRule)
    .refine((a) => a.filter(isTerminalAction).length <= 1, {
      message: 'at most one terminal action',
    }),
  onError: z.enum(['allow', 'block']),
});

const PolicyKeySchema = z.strictObject({
  kid: z.string().regex(KID),
  alg: z.enum(POLICY_ALGS),
  pub: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  notAfter: z.number().int().min(0),
});

const Seconds = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const Lifetime = z.number().int().min(300).max(86400);

export const PolicyBundlePayloadSchema = z
  .strictObject({
    v: z.literal(1),
    siteId: z.string().regex(copyRegex(SITE_ID)),
    siteKey: z.string().regex(copyRegex(SITE_KEY)),
    challengeBase: z
      .string()
      .max(300)
      .refine(
        (s) => {
          const m = /^https:\/\/([a-z0-9.-]+)(?::[0-9]{1,5})?$/.exec(s);
          return m !== null && canonicalizeHostname(m[1] as string) === m[1];
        },
        { message: 'challengeBase must be https://host[:port], no path' },
      ),
    version: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
    issuedAt: Seconds,
    notBefore: Seconds,
    expiresAt: Seconds,
    failMode: z.enum(['open', 'closed']),
    onNonCanonical: z.enum(['block-writes', 'block']).default('block-writes'),
    minIat: Seconds,
    /** Optional; true asks integrations that support `X-RG-Sig` (and hold a `sigSecret`) to sign the decision headers. Absent means false. */
    sigHeader: z.boolean().optional(),
    /** Optional kill switch; emitted only when true. A verified bundle with `disabled: true` makes every verifier pass every request through. Absent means false. */
    disabled: z.boolean().optional(),
    revokedJti: z.array(z.string().regex(JTI)).max(POLICY_LIMITS.maxRevokedJti),
    session: z
      .strictObject({ ttl: Lifetime, max: Lifetime, clearanceTtl: Lifetime })
      .refine((s) => s.ttl <= s.max, { message: 'ttl must not exceed max' }),
    hosts: z.array(HostPattern).min(1).max(POLICY_LIMITS.maxSiteHosts),
    tokenKeys: z.array(PolicyKeySchema).min(1).max(4),
    policies: z.array(PolicyRuleSchema).max(POLICY_LIMITS.maxPolicies),
  })
  .refine(
    (p) =>
      p.expiresAt > p.notBefore && p.expiresAt - p.notBefore <= POLICY_LIMITS.bundleValiditySeconds,
    { message: 'validity window must be positive and at most 24 hours' },
  )
  .refine((p) => new Set(p.policies.map((r) => r.id)).size === p.policies.length, {
    message: 'duplicate rule id',
  });

export type PolicyAction = z.infer<typeof PolicyActionSchema>;
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;
export type PolicyBundlePayload = z.infer<typeof PolicyBundlePayloadSchema>;
export type PolicyKey = z.infer<typeof PolicyKeySchema>;
