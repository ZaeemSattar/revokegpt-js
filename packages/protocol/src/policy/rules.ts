import { compileGlob, globMatch } from './glob.js';
import { POLICY_LIMITS } from './limits.js';
import {
  isSafeRedirectLocation,
  isTerminalAction,
  type PolicyRule,
  PolicyRuleSchema,
  patternCovers,
} from './schema.js';

export type RuleErrorCode =
  | 'schema'
  | 'too-many-rules'
  | 'duplicate-id'
  | 'host-not-allowed'
  | 'redirect-not-allowed'
  | 'blocks-rg-path';
export type RuleLintCode =
  | 'shadowed'
  | 'catch-all-first'
  | 'allow-after-block'
  | 'blocks-rg-path'
  | 'block-all';

const RESERVED = ['/__rg/return', '/__rg/session'] as const;
const BLOCKING = ['block', 'requireToken', 'challengePage', 'redirect'];

function blocksReserved(r: PolicyRule): boolean {
  if (!r.enabled) return false;
  if (!r.actions.some((a) => BLOCKING.includes(a.type))) return false;
  if (!r.match.methods.some((m) => m === 'POST' || m === '*')) return false;
  const g = compileGlob(r.match.path);
  return g !== null && RESERVED.some((p) => globMatch(g, p));
}

/**
 * Validate a rule list for saving and signing (the editor and the bundle job). Errors name the
 * rule index and a code; a rule with a schema error reports only `schema`. `siteHosts` are the
 * site's hostname patterns: every rule host and every absolute redirect host must be covered.
 */
export function validateRules(
  rules: readonly unknown[],
  siteHosts: readonly string[],
): { ok: true } | { ok: false; errors: { index: number; code: RuleErrorCode }[] } {
  const errors: { index: number; code: RuleErrorCode }[] = [];
  if (!Array.isArray(rules)) return { ok: false, errors: [{ index: 0, code: 'schema' }] };
  if (rules.length > POLICY_LIMITS.maxPolicies)
    errors.push({ index: POLICY_LIMITS.maxPolicies, code: 'too-many-rules' });
  const seen = new Set<string>();
  rules.forEach((raw, index) => {
    const parsed = PolicyRuleSchema.safeParse(raw);
    if (!parsed.success) {
      errors.push({ index, code: 'schema' });
      return;
    }
    const r = parsed.data;
    if (seen.has(r.id)) errors.push({ index, code: 'duplicate-id' });
    seen.add(r.id);
    if (!r.match.hosts.every((h) => siteHosts.some((s) => patternCovers(s, h))))
      errors.push({ index, code: 'host-not-allowed' });
    if (
      r.actions.some((a) => a.type === 'redirect' && !isSafeRedirectLocation(a.location, siteHosts))
    )
      errors.push({ index, code: 'redirect-not-allowed' });
    if (blocksReserved(r)) errors.push({ index, code: 'blocks-rg-path' });
  });
  return errors.length === 0 ? { ok: true } : { ok: false, errors };
}

function terminalOf(r: PolicyRule): string | null {
  const t = r.actions.find(isTerminalAction);
  return t ? t.type : null;
}

function normGlob(p: string): string {
  return p.length > 1 && p.endsWith('/') ? p.slice(0, -1) : p;
}

function pathCovers(earlier: string, later: string): boolean {
  const e = compileGlob(earlier)?.canonical ?? normGlob(earlier);
  const l = compileGlob(later)?.canonical ?? normGlob(later);
  if (e === l || e === '/**') return true;
  if (!e.endsWith('/**')) return false;
  const prefix = e.slice(0, -3);
  if (prefix.includes('*')) return false;
  return l === prefix || l.startsWith(`${prefix}/`);
}

function methodsCover(earlier: readonly string[], later: readonly string[]): boolean {
  return later.every(
    (m) =>
      earlier.includes(m) ||
      (earlier.includes('*') && m !== 'OPTIONS') ||
      (m === 'HEAD' && earlier.includes('GET')),
  );
}

function covers(e: PolicyRule, l: PolicyRule): boolean {
  return (
    e.enabled &&
    e.when === undefined &&
    terminalOf(e) !== null &&
    pathCovers(e.match.path, l.match.path) &&
    methodsCover(e.match.methods, l.match.methods) &&
    l.match.hosts.every((h) => e.match.hosts.some((s) => patternCovers(s, h)))
  );
}

/** Advisory findings for a rule list that is already valid. Never blocks saving. */
export function lintRules(rules: readonly PolicyRule[]): { index: number; code: RuleLintCode }[] {
  const out: { index: number; code: RuleLintCode }[] = [];
  rules.forEach((r, i) => {
    if (!r.enabled) return;
    const matchesAll =
      r.when === undefined &&
      normGlob(r.match.path) === '/**' &&
      r.match.methods.length === 1 &&
      r.match.methods[0] === '*';
    const t = terminalOf(r);
    if (matchesAll && t !== null && i < rules.length - 1)
      out.push({ index: i, code: 'catch-all-first' });
    // block-all: a terminal block of every path for GET (methods `*`, or including GET). The database
    // asks for the confirmation word on exactly this shape (private.policy_blocks_all).
    const blocksAllGet =
      r.when === undefined &&
      (compileGlob(r.match.path)?.canonical ?? normGlob(r.match.path)) === '/**' &&
      (r.match.methods.includes('*') || r.match.methods.includes('GET')) &&
      t === 'block';
    if (blocksAllGet) out.push({ index: i, code: 'block-all' });
    if (blocksReserved(r)) out.push({ index: i, code: 'blocks-rg-path' });
    for (let j = 0; j < i; j++) {
      const e = rules[j] as PolicyRule;
      if (covers(e, r)) {
        out.push({
          index: i,
          code: t === 'allow' && terminalOf(e) === 'block' ? 'allow-after-block' : 'shadowed',
        });
        break;
      }
    }
  });
  return out;
}
