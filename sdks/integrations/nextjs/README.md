# @revokegpt/firewall-next

RevokeGPT firewall for Next.js (protocol v1, section 18): `proxy.ts` on Next 16 and a `middleware.ts` shim on
Next 15.5. All decisions come from [`@revokegpt/firewall`](../firewall/README.md); this package only adapts
`NextRequest` and `NextResponse`.

**Node runtime only.** The firewall needs Node's `fetch`, WebCrypto and a module-level bundle cache. Next 16's `proxy.ts`
runs on Node; on Next 15.5 set `runtime: 'nodejs'` in the middleware `config`. The Edge runtime is not supported.

## Next 16: `proxy.ts`

```ts
// proxy.ts
import { withRevokeGPT } from '@revokegpt/firewall-next/proxy';

export const proxy = withRevokeGPT({
  siteKey: process.env.RG_SITE_KEY!,
  secretKey: process.env.RG_SECRET_KEY,
});

// Next reads `config` statically, so the literal must be in this file.
export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };
```

## Next 15.5: `middleware.ts`

```ts
// middleware.ts
import { withRevokeGPTMiddleware } from '@revokegpt/firewall-next/middleware';

export const middleware = withRevokeGPTMiddleware({ siteKey: process.env.RG_SITE_KEY! });
export const config = {
  runtime: 'nodejs',
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

(On Next 15 use `next.config.mjs`: Next 15 loads `next.config.ts` through the TypeScript JS API, which TypeScript 7 lacks.)

## Routing must stay case-sensitive (Ruling 14)

Firewall rules match paths case-sensitively (protocol section 18.3), so `/ADMIN` is not `/admin`. Next.js routes case-sensitively; an `i`-flagged rewrite or a case-insensitive host in front does not. If the origin
behind this integration routes case-insensitively (IIS, a case-folding proxy or framework, a case-insensitive file
system), `/ADMIN` reaches the `/admin` handler while a rule on `/admin` never sees it. Make the origin case-sensitive
or write the rule for each spelling the origin serves.

## The matcher

`/((?!_next/static|_next/image|favicon.ico).*)` is the documented matcher (exported as `MATCHER`). It excludes only the
immutable build output and keeps everything an attacker could use inside the firewall:

- **Server Functions.** A Server Function call is a `POST` to the page's own URL with a `Next-Action` header. It matches
  the page's rules, so a rule for `/admin` covers `/admin` Server Function POSTs too.
- **`/_next/data/<buildId>/<page>.json`** (Pages Router page data) is not excluded. The adapter evaluates it as `/<page>`
  (`index.json` as `/`), so a rule for `/admin` also covers `/_next/data/<id>/admin.json`. This holds with and without
  `skipProxyUrlNormalize`.
- `/__rg/*`, API routes and route handlers.

A narrower matcher (for example `['/admin/:path*']`) leaves every other path, including `/__rg/session` and
`/__rg/return`, unprotected and unserved: the reserved routes must stay inside the matcher.

## Target and `skipProxyUrlNormalize`

The rule target is `req.nextUrl.pathname + req.nextUrl.search`. By default (recommended, and what the examples use) Next
hands the proxy a normalised URL: `/_next/data/<id>/x.json` arrives as `/x`, the `basePath` and locale prefix and a
trailing `.rsc` are gone. With `skipProxyUrlNormalize: true` (Next 16; `skipMiddlewareUrlNormalize` in 15) the URL is
closer to what was received. Pass `skipUrlNormalize: true` to `withRevokeGPT` when you turn it on. Checked against Next
16.4.3 (probe: `/admin.rsc` arrives as `/admin`, `/admin.prefetch.rsc` as `/admin.prefetch`,
`/admin.segments/_tree.segment.rsc` as `/admin.segments/_tree.segment`, `/_next/data/B/p.json` unchanged). The adapter
always evaluates `/_next/data/<id>/p.json` as `/p` (`index` as `/`). With `skipUrlNormalize` it also strips `.segments/...`
and a trailing `.prefetch`, but only for requests carrying Next's own RSC/prefetch headers (`RSC: 1`,
`Next-Router-Prefetch`, `Next-Router-Segment-Prefetch`), so a real route named `/x.prefetch` is evaluated as itself.
Set `skipTrailingSlashRedirect: true` so `/admin/` reaches the proxy unchanged instead of being redirected first.

## Redirect `Location`

Next's adapter throws on a relative `Location`, and Next 15 always rewrites it to an absolute URL on its own internal
origin, so the adapter makes every same-site `Location` absolute itself, from the request's `Host` header (the host the
firewall decided on) and the scheme: `https` by default, or `X-Forwarded-Proto` (`http`/`https`) when you pass
`trustProxy: true` to `withRevokeGPT` (only behind a proxy that overwrites that header). It never uses
`req.nextUrl`'s server origin. Next 16 relativises it again when the host matches.

`x-matched-path` can be sent by a visitor like any header (platform adapters normally overwrite it); the adapter never
trusts it for a decision and only refuses (404) a request whose `x-matched-path` names the `/__rg` namespace.
`x-middleware-subrequest` is never trusted or honoured by this adapter either.

## Minimum Next versions

Use Next 15.5 or newer (peer range `>=15.5`; tested on 15.5.28 and 16.4.3). Releases before the CVE-2025-29927 fixes
(15.2.3 and 14.2.25 or later in their lines) let a visitor skip middleware with a forged `x-middleware-subrequest` header,
which would bypass the firewall entirely; never run a self-hosted Next older than those fixes.

## Behaviour

- On a pass the request headers get every `x-rg-*` removed and the decision headers set, through
  `NextResponse.next({ request: { headers } })` (or your `pass` option, for example a `NextResponse.rewrite` to another
  origin). Those headers never appear in a block, challenge or reserved-route response, which carry
  `Cache-Control: no-store`.
- `POST /__rg/return` is the only place a body is read (capped at 4 KiB).

## Runtime facts (Next 16.4.3 and 15.5.28, Node runtime)

Next runs some request normalisation and routing before `proxy.ts` / `middleware.ts`. The vectors are not edited; the
affected conformance rows are:

- **`//admin`, `/admin//secret`, backslash and absolute-form targets** are answered by Next itself with a `308`
  redirect to the cleaned path before the proxy runs (rows `focus1-double-slash-stricter-wins`,
  `focus1-double-slash-nested`, `focus1-backslash-is-400`, `focus1-absolute-form-is-400`,
  `stricter-raw-blocks-collapsed-allows`, `stricter-collapsed-blocks-raw-allows`). The request that follows the
  redirect reaches the proxy as the clean path and gets the strict decision, and nothing reaches the origin from the
  unclean form.
- **Asterisk-form (`OPTIONS *`)** makes Next throw `Invalid URL` (500) on Next 16 before the proxy runs
  (`focus1-asterisk-form-is-400`). It is refused, not allowed.
- The conformance harness ignores a URL fragment when it matches an absolute `Location` to the expected path, so the two
  rows with `#frag` (`returnPath/query-and-fragment`, `routes/return-sets-clearance-and-clears-return`) fail wherever
  the adapter's absolute `Location` is not relativised by Next (harness limitation; the Location is correct).

## Conformance

Build the package and the example, then run the harness (49xx port block):

```
pnpm --filter @revokegpt/firewall-next build
pnpm --filter @revokegpt/firewall-next-example16 build
pnpm --filter @revokegpt/firewall-next-example15 build
node example/run-conformance.ts 16   # 4910 API, 4911 origin, 4914 app: 165/174
node example/run-conformance.ts 15   # 4910 API, 4911 origin, 4915 app: 166/174 (see runtime facts)
```

The Next 15 example pins TypeScript 5.9.3 (Next 15 cannot use TypeScript 7).
