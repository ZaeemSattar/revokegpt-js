import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { type NodeConfig, type NodeFirewall, revokeGPTNodeHttp } from './node-http.js';

const MARK = Symbol.for('revokegpt.firewall');

export interface ExpressFirewall extends RequestHandler {
  readonly firewall: NodeFirewall['firewall'];
}

type Layer = { handle?: unknown; route?: unknown; name?: string };

function stackOf(app: unknown): Layer[] {
  const a = app as { router?: { stack?: Layer[] }; _router?: { stack?: Layer[] } } | undefined;
  return a?.router?.stack ?? a?._router?.stack ?? [];
}

/**
 * Throws unless the app routes case-sensitively. Firewall rules match paths case-sensitively
 * (protocol section 18, Ruling 14); Express defaults to case-insensitive routing, so `/ADMIN`
 * would be routed to the `/admin` handler while a rule on `/admin` never sees it.
 * Fix: `app.set('case sensitive routing', true)` before mounting the firewall.
 */
export function assertCaseSensitive(app: unknown): void {
  const get = (app as { get?: (k: string) => unknown } | undefined)?.get;
  if (typeof get !== 'function' || get.call(app, 'case sensitive routing') !== true)
    throw new Error(
      "[revokegpt] Express 'case sensitive routing' must be enabled: app.set('case sensitive routing', true). Firewall rules match paths case-sensitively, and Express would route /ADMIN to /admin.",
    );
}

/**
 * Warns when something is mounted before the firewall: any route, router or other middleware
 * ahead of it (body parsers, static files, a router) can answer a request the firewall never sees.
 * Returns the number of layers that sit before it, or -1 when it is not mounted on `app`.
 */
export function checkMountOrder(
  app: unknown,
  warn: (message: string) => void = (m) => console.warn(m),
): number {
  assertCaseSensitive(app);
  const stack = stackOf(app);
  const at = stack.findIndex(
    (l) => (l.handle as { [MARK]?: boolean } | undefined)?.[MARK] === true,
  );
  if (at < 0) return -1;
  const before = stack.slice(0, at).filter((l) => l.name !== 'query' && l.name !== 'expressInit');
  if (before.length > 0)
    warn(
      `[revokegpt] the firewall is mounted after ${before.length} other layer(s) (${before
        .map((l) => (l.route !== undefined ? 'route' : l.name || 'anonymous'))
        .join(', ')}); requests they answer are never checked. Mount revokeGPTExpress() first.`,
    );
  return before.length;
}

/**
 * Express middleware. Mount it FIRST (`app.use(revokeGPTExpress(cfg))` before any router, body
 * parser or static handler). It reads `req.originalUrl` (the target as received, never the
 * mount-relative `req.url`) and the Host header as sent: Express's `trust proxy` does not change
 * the host the firewall uses. Mounted after a router it warns on the first request, and
 * `checkMountOrder(app)` reports it at startup. It refuses to pass any request (and
 * `checkMountOrder` throws) unless `case sensitive routing` is on.
 */
export function revokeGPTExpress(cfg: NodeConfig): ExpressFirewall {
  const nodeFw = revokeGPTNodeHttp({ integration: 'express/0.0.0', ...cfg });
  let checked = false;
  const mw = (req: Request, res: Response, next: NextFunction): void => {
    if (!checked) {
      try {
        checkMountOrder(req.app); // throws unless case sensitive routing is on
        checked = true;
      } catch (e) {
        next(e); // never lets a request through an unsafe setup
        return;
      }
    }
    nodeFw(req, res, req.originalUrl).then(
      (passed) => {
        if (passed) next();
      },
      () => {
        if (!res.headersSent) res.status(503).end();
      },
    );
  };
  (mw as unknown as { [MARK]: boolean })[MARK] = true;
  return Object.assign(mw, { firewall: nodeFw.firewall });
}
