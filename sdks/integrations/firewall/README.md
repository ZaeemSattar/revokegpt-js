# @revokegpt/firewall

The runtime core of the RevokeGPT firewall integrations (protocol v1, section 18). It is a shell around
the reference decision engine in `@revokegpt/protocol` (`decide`, `verifyBundle`, `verifySession`,
`stripRgHeaders`, `isSafeReturnPath`): it never re-implements matching or verification. Framework
adapters (Express, Hono, Next.js and the rest) turn their request into an `FwRequest`, call `handle`, and
forward or answer.

```ts
import { createFirewall } from '@revokegpt/firewall';

const fw = createFirewall({
  siteKey: process.env.RG_SITE_KEY,
  secretKey: process.env.RG_SECRET_KEY, // rgsk_..., needed only for requireToken rules
  integration: 'express/1.0.0',
});

const out = await fw.handle({ method, host, rawTarget, headers, cookies, body });
if (out.type === 'respond') send(out.status, out.headers, out.body);
else forward({ delete: out.stripHeaders, set: out.setHeaders });
```

`FwRequest = { method, host, rawTarget, headers: [name, value][], cookies, body? }`.
`rawTarget` is the request target exactly as received (query included), before any framework rewriting.

## What it does

- **Bundle.** `GET {apiBase}/v1/policies/{siteKey}`, verified offline against pinned Ed25519 keys. Single-flight
  (100 concurrent cold requests make one fetch), refetched every 60 s plus 0 to 20 s of jitter. A failed or
  invalid refresh keeps the last good bundle until `expiresAt + 6 h`; after that the bundle's `failMode`
  applies (`open`: pass with `X-RG-Verdict: none`; `closed`: 503). A lower `version` than any seen is refused
  (`VersionStore` remembers the highest per site; in memory by default). A bad signature counts as no bundle.
  Before any bundle was ever verified, `initialFailMode` applies: `'open'` (default) passes with `X-RG-Verdict: none`, `'closed'` answers 503; an authentic 404 (no published policies) always passes (protocol section 18.5).
- **Sessions.** `__Host-rg_c` (clearance) and `__Host-rg_s` (session) are verified offline against the
  bundle's `tokenKeys`, for this site and this host. A token for another host is no session and costs no call.
- **Action tokens** come only from the `X-RG-Token` header (20 to 4096 characters of base64url and `.`). A
  `requireToken` rule verifies it with `POST /v1/siteverify` (`Authorization: Bearer rgsk_...`,
  `X-RG-Integration`, 2 s timeout, one retry on a connection error only) behind a circuit breaker (5
  consecutive failures open it for 30 s; the rule's `onError` applies with no call).
- **Reserved routes**, served before any rule:
  - `POST /__rg/session`: verifies `X-RG-Session-Init`, sets `__Host-rg_s`, answers 204.
  - `POST /__rg/return`: the only place a body is read (`req.body()`, urlencoded, at most 4 KiB, the single
    field `rg_clearance`). A clearance for this host sets `__Host-rg_c`, clears `__Host-rg_r` and answers 303
    to the return path if `isSafeReturnPath` accepts it, else `/`.
  - Any other `/__rg/...` path (any spelling) is a 404 and never reaches the origin.
- **Challenge.** A navigation (`Sec-Fetch-Mode: navigate` and `Accept: text/html`, GET) gets a 303 and a
  `__Host-rg_r` cookie holding the normalized path and query (at most 2 KiB, only if it is a safe return
  path and a valid cookie value). Anything else gets `403` plus `X-RG-Action: challenge`, never a redirect.
- **Responses** from the integration always carry `Cache-Control: no-store` and `Vary: Cookie`. Cookies are
  `HttpOnly; Secure; SameSite=Lax; Path=/` with a `Max-Age`.
- **Headers.** `pass` lists `stripHeaders` (every `x-rg-*` and `x_rg_*`, duplicates included, names as
  received): delete them first, then set `setHeaders` (`X-RG-Score`, `X-RG-Verdict`, `X-RG-Rule`,
  `X-RG-Path`, rule `setHeader`s, and `X-RG-Sig` when `sigSecret` is set). `X-RG-Sig` is
  `t=<unix seconds>,v1=<hex HMAC-SHA256>` over `t`, host, method, normalized path, score, verdict and rule index
  joined by newlines, keyed with `sigSecret`.
- **Logging.** The optional `log` callback gets `{ decisionId, ruleIndex, action }` only. Tokens, cookies,
  keys and query strings are never logged.

## Private bundles and X-RG-Sig

- **Private bundle.** When the owner marks the bundle private, `GET /v1/policies/<siteKey>` needs
  `Authorization: Bearer <secretKey>`. The core sends it on every bundle fetch whenever a `secretKey` is configured, to
  the configured `apiBase` only (redirects are never followed). A 401 or 403 is logged once as the decision-log event
  `config-error:bundle-unauthorized` (never the secret) and is handled as an outage, so `initialFailMode` governs it.
- **X-RG-Sig.** Signed only when the bundle's settings turn it on (`sigHeader: true`) AND a `sigSecret` is configured. If
  the bundle asks for it and no secret is set, the core logs `config-warning:sig-secret-missing` once and signs nothing.
- **siteverify.** The secret travels only as the Bearer; one 2 s budget covers both attempts, the send and the body, and
  the single retry happens only after a refused or unresolvable connection.

## Configuration

`siteKey`, `secretKey?`, `apiBase?` (https; http only for localhost), `pinnedKeys?` (default
`PINNED_POLICY_KEYS`; tests pass explicit keys), `integration`, `sigSecret?`, `fetch?`, `now?` (milliseconds),
`store?`, `log?`, `initialFailMode?`, `pinTestKeys?` (test only: pins the TEST keys and accepts the non-canonical conformance site key; otherwise the site key must be canonical and the bundle's siteKey is always checked), `bundleRefreshMs?` (default 60000; shorter values are for the conformance
harness).

## Conformance

`tools/policy-conformance` (`rg-conformance --target http://127.0.0.1:<port> [--only decide|routes]`) replays
the `policy.json` vectors over raw HTTP against a running integration. The env contract is in `tools/policy-conformance/README.md`. The vectors with their own `now` (stale bundles) need a controllable clock and run in this
package's unit tests instead.
