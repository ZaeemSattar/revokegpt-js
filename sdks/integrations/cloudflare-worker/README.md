# RevokeGPT firewall for Cloudflare Workers

A Worker template that fronts your origin with the RevokeGPT signed-policy firewall (protocol v1, section 18).
It wraps `createFirewall` from `@revokegpt/firewall`; no decision logic lives here.

```
src/index.ts      export default { fetch(request, env, ctx) }
wrangler.jsonc    template config (vars, optional KV)
example/          local example: node example/serve.mjs  (wrangler dev in front of RG_ORIGIN)
```

## Setup

1. Put the Worker on a route in front of your origin (`routes` in `wrangler.jsonc`). An allowed request is
   forwarded with `fetch(request)`, so it reaches the origin. Or set `RG_ORIGIN` to forward to a fixed origin URL
   (same path and query).
2. Vars: `RG_SITE_KEY` (`rgpk_...`), `RG_API_BASE`. Secret: `wrangler secret put RG_SECRET_KEY` (needed only for
   `requireToken` rules). Optional: `RG_SIG_SECRET` (secret, enables `X-RG-Sig`), `RG_INITIAL_FAIL_MODE`
   (`open` default, or `closed`), `RG_STATE` (a KV binding, see below).
3. `RG_PIN_TEST_KEYS=1` is for the conformance harness only. Workers have no `NODE_ENV`, so the switch is a var. It is
   accepted only with a non-canonical site key AND a loopback `RG_API_BASE`; any other combination makes the Worker
   answer `503` to everything (it never forwards on a config error).
4. `RG_BUNDLE_REFRESH_MS` (default 60000) exists for the conformance harness.

## How it works

- **Raw target.** The Worker receives a parsed URL, so the target is `new URL(request.url)` `pathname + search`.
  workerd and the Fetch API normalise `..`, `.`, backslashes and a few other forms before your code runs
  (see the runtime facts below); the vectors prove what still reaches the Worker.
- **Bundle cache.** One bundle per isolate (single-flight, refetched every 60 s plus jitter). A bundle the core has verified is also
  written to the Cache API (colo-wide, 24 h), and a network failure or non-200/404 answer from the API falls back to
  that copy. It is still verified for signature, site, expiry and version, so it can never weaken a decision. An
  authentic 404 (no published policies) is never answered from the cache and passes.
- **Background refresh.** The core refetches in the background when the interval is due; the Worker registers that
  work with `ctx.waitUntil` (a keep-alive released as soon as the refresh stores its version, at most 3 s).
- **Version store.** Without `RG_STATE` the highest bundle version is remembered in the isolate. Bind a KV namespace
  as `RG_STATE` to remember it across isolates (replay protection for older bundles). **Recommended in production:**
  without it, a cold isolate that starts during an API outage has no rollback floor and accepts any still-valid older
  bundle until the API is reachable again.
- **Headers.** Every `x-rg-*` / `x_rg_*` request header is deleted before the origin sees it, then the decision's
  `X-RG-Score`, `X-RG-Verdict`, `X-RG-Rule`, `X-RG-Path`, rule `setHeader`s and `X-RG-Sig` are set. They go to the
  origin only, never onto block, challenge or respond answers, which always carry `Cache-Control: no-store`.
- **Bodies.** Only `POST /__rg/return` reads a body (urlencoded, at most 4 KiB: the Worker reads at most 4097 bytes).
  The action token comes only from `X-RG-Token`.
- **Cookies.** A cookie name that appears twice in `Cookie` is dropped (no session) because which copy the browser
  meant is unknowable.
- **Fail modes.** Before any bundle was ever verified: `open` passes with `X-RG-Verdict: none`, `closed` gives 503.
  An outage is retried no sooner than every 10 s.

## Routing must stay case-sensitive (Ruling 14)

Firewall rules match paths case-sensitively (protocol section 18.3), so `/ADMIN` is not `/admin`. The Worker forwards to any origin. If the origin
behind this integration routes case-insensitively (IIS, a case-folding proxy or framework, a case-insensitive file
system), `/ADMIN` reaches the `/admin` handler while a rule on `/admin` never sees it. Make the origin case-sensitive
or write the rule for each spelling the origin serves.

## Cache keys and cookies

The firewall's challenge and session answers set cookies and carry `Vary: Cookie` plus `Cache-Control: no-store`,
so Cloudflare never caches them. If you enable caching for origin responses behind this Worker, make sure the cache
key does not let one visitor's response (decided for their `__Host-rg_c` / `__Host-rg_s` session) serve another: the
Worker decides before the cache, but a cache rule that ignores cookies applies to responses the Worker already
allowed, which is correct only for content that is the same for every cleared visitor. Never cache a response that
depends on `X-RG-Score` or `X-RG-Verdict`.

## Runtime facts (workerd acts before the Worker)

Recorded from `test/vectors.test.ts` (runs `policy.json` through the handler) and from `rg-conformance` against
`wrangler dev` (vectors are never edited). Every one is still a refusal or a consistent normalisation; none allows
a request the policy blocks.

- Workers receive a parsed URL. These rows reach the Worker already rewritten: `focus1-dot-segment-resolved-then-blocked`
  (`/Admin/../admin/x` becomes `/admin/x`), `focus1-encoded-dot-dot-GET-strict` and `-POST` (`/%2e%2e/admin` becomes
  `/admin`), `focus1-backslash-is-400` (`\` becomes `/`, so it is blocked by the path rule, 403 instead of 400),
  `focus1-absolute-form-is-400` (403 instead of 400), `focus1-raw-newline-is-400`, `raw-non-ascii-request-is-400`
  (percent-encoded), `stricter-collapsed-blocks-raw-allows` (`/a//../b` becomes `/a/b`, which the origin also
  receives, so it is consistent), `query-after-blocked-path` (fragment dropped). The Worker forwards the same
  rewritten target it decided on.
- workerd refuses these before the Worker runs: `lowercase-method-refused` (501, and the Fetch API upper-cases a
  method), `host-with-space-refused` (500), `focus1-asterisk-form-is-400` (500, `OPTIONS *`),
  `punycode-host-from-unicode` (400 from the server; still a refusal), and methods with whitespace or empty (not
  buildable).
- workerd rewrites the `Host` header to the URL authority, dropping userinfo: `host-with-userinfo-refused`
  (`Host: a@example.com`) reaches the Worker as `example.com`, so the policy for `example.com` applies and the
  request is forwarded. The userinfo is not an attack surface here (the origin sees `example.com` too).
- `rg-conformance` result against `wrangler dev` of `example/`: 166 of 174 rows pass; the 8 failures are exactly the
  rows above (lowercase method, unicode host, host with space, userinfo host, backslash, absolute form, asterisk
  form, collapsed path).
- 3 of the 127 decide rows carry their own `now`; `test/vectors.test.ts` marks them `it.skip` (the Worker never runs them end to end). Rows with their own `now` and rows the harness skips (empty or whitespace methods, CR/LF or non-ASCII return paths)
  are covered by the core's unit vectors.

## Tests

`pnpm --filter @revokegpt/firewall-cloudflare test` (vitest-pool-workers): every decide and headers row through the
handler, plus `SELF.fetch` tests (client `X-RG-Score` is gone at the origin, a `requireToken` POST without a token is
403 and never reaches the origin, reserved routes, the 4 KiB body bound, the KV version store, the Cache API
fallback). Conformance:

```
PORT=4812 RG_API_BASE=http://127.0.0.1:4810 RG_SITE_KEY=rgpk_conformance RG_SECRET_KEY=rgsk_conformance \
  RG_ORIGIN=http://127.0.0.1:4811 RG_BUNDLE_REFRESH_MS=200 RG_PIN_TEST_KEYS=1 node example/serve.mjs &
node tools/policy-conformance/src/cli.ts --target http://127.0.0.1:4812 --api-port 4810 --origin-port 4811
```
