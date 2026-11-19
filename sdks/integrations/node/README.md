# @revokegpt/firewall-node

RevokeGPT firewall middleware (protocol v1, section 18) for Express, Fastify and plain `node:http`. Each
adapter only turns the request into an `FwRequest` and applies the `FwResult`; every decision comes from
[`@revokegpt/firewall`](../firewall/README.md).

```ts
import express from 'express';
import { revokeGPTExpress } from '@revokegpt/firewall-node/express';

const app = express();
app.use(
  revokeGPTExpress({ siteKey: process.env.RG_SITE_KEY!, secretKey: process.env.RG_SECRET_KEY }),
); // FIRST
```

```ts
import Fastify from 'fastify';
import { revokeGPTFastify } from '@revokegpt/firewall-node/fastify';

const app = Fastify();
await app.register(revokeGPTFastify({ siteKey: process.env.RG_SITE_KEY! }));
```

```ts
import { createServer } from 'node:http';
import { revokeGPTNodeHttp } from '@revokegpt/firewall-node';

const fw = revokeGPTNodeHttp({ siteKey: process.env.RG_SITE_KEY! });
createServer(async (req, res) => {
  if (await fw(req, res)) app(req, res); // false: the firewall already answered
}).listen(8080);
```

`integration` defaults to `express/0.0.0`, `fastify/0.0.0` and `node-http/0.0.0`. All other options are the core's
(`FirewallConfig`).

## Required routing settings (Ruling 14)

Firewall rules match paths case-sensitively (protocol section 18). If the framework routes case-insensitively, `/ADMIN`
reaches the `/admin` handler but a rule on `/admin` never sees it.

- **Express** refuses to pass any request (the middleware hands a clear error to `next`, and `checkMountOrder(app)`
  throws at startup) unless `app.set('case sensitive routing', true)` was called. Express's default is `false`.
- **Fastify** refuses to register (`app.ready()` rejects) when the instance was built with `caseSensitive: false` or
  `routerOptions: { caseSensitive: false }`. The default is `true`.

## Express

- **Mount it first.** Anything before it (a router, `express.static`, a body parser, another middleware) can answer a
  request the firewall never sees. The middleware inspects the app's layer stack on the first request and
  `checkMountOrder(app)` does the same at startup (it returns the number of layers ahead of the firewall and warns);
  call it after you finished wiring the app.
- **Target.** It uses `req.originalUrl`, the target as received. `req.url` is relative to a mount prefix and is not
  used, so `app.use('/admin', router)` cannot move a request out of a rule.
- **Host and `trust proxy`.** The host is the `Host` header as sent. `trust proxy` and `X-Forwarded-Host` are ignored on
  purpose: that header is client-controlled unless every hop rewrites it. Behind a reverse proxy make the proxy
  forward the original `Host` (nginx `proxy_set_header Host $host;`).
- It never reads a body except for `POST /__rg/return` (capped at 4 KiB), so mounting it before `express.json()` is
  correct and required.

## Fastify

- A plugin that opts out of encapsulation (`skip-override`), so its `onRequest` hook covers routes in every child
  scope. Register it on the root instance before the routes.
- **Target.** `req.raw.url`; if the `rewriteUrl` option moved it, `req.raw.originalUrl` (the target as received) is used
  and a warning is logged once.

## Pass behaviour

On a pass the adapter deletes every `x-rg-*` / `x_rg_*` header the client sent (from `req.headers` and
`req.rawHeaders`), then sets the decision headers (`X-RG-Score`, `X-RG-Verdict`, `X-RG-Rule`, rule `setHeader`s,
`X-RG-Sig`). A client header named like a rule `setHeader` (any case, every duplicate) is removed first, so the origin sees
exactly the rule's value. Those headers belong to your origin and are never copied into a block, challenge or reserved-route
response, which carry `Cache-Control: no-store`.

## Runtime facts

- **Fastify rejects some malformed targets before any hook runs.** An overlong UTF-8 sequence in the path
  (vectors `focus1-overlong-utf8-GET-strict`, `focus1-overlong-utf8-DELETE`) is answered with `400` by the router
  (`FST_ERR_BAD_URL`) before `onRequest`. The request is still refused and never reaches the origin, but the vector
  expects `403`, so the conformance run for Fastify is 172/174. The vectors are not edited.
- Node's HTTP parser repairs a request line with an empty or spaced method; those rows are skipped by the harness.

## Conformance

```
pnpm build
node example/run-conformance.ts express   # ports 4910 (API), 4911 (origin), 4912 (app)
node example/run-conformance.ts fastify   # ports 4910, 4911, 4913
```

Results: Express 174/174, Fastify 172/174 (the two runtime-fact rows above).
