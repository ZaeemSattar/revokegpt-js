import { createFirewall } from '@revokegpt/firewall';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { applyPass, type NodeConfig, toFwRequest } from './node-http.js';

/**
 * Fastify plugin: an `onRequest` hook on the whole instance (it opts out of encapsulation, so
 * register it on the root instance before any route). It evaluates the target as received (`req.raw.originalUrl` when
 * `rewriteUrl` moved `req.raw.url`, else `req.raw.url`); a `rewriteUrl` is warned about once.
 */
export function revokeGPTFastify(cfg: NodeConfig) {
  const firewall = createFirewall({ integration: 'fastify/0.0.0', ...cfg });
  const plugin = (app: FastifyInstance, _opts: unknown, done: (err?: Error) => void): void => {
    const init = (
      app as unknown as {
        initialConfig?: { caseSensitive?: boolean; routerOptions?: { caseSensitive?: boolean } };
      }
    ).initialConfig;
    // Firewall rules match paths case-sensitively (Ruling 14); Fastify's router must too.
    const ro = init?.routerOptions;
    if ((ro !== undefined ? ro.caseSensitive : init?.caseSensitive) === false) {
      done(
        new Error(
          '[revokegpt] Fastify caseSensitive:false is refused: rules match paths case-sensitively, and the router would serve /ADMIN as /admin. Remove it (the default is true).',
        ),
      );
      return;
    }
    let warned = false;
    app.addHook('onRequest', async (req: FastifyRequest, reply: FastifyReply) => {
      // Fastify's rewriteUrl moves req.raw.url and keeps the received target in raw.originalUrl.
      const received = (req.raw as { originalUrl?: string }).originalUrl;
      if (received !== undefined && received !== req.raw.url && !warned) {
        warned = true;
        console.warn(
          '[revokegpt] Fastify rewriteUrl is set; the firewall evaluates the target as received (req.raw.originalUrl), not the rewritten one.',
        );
      }
      const out = await firewall.handle(toFwRequest(req.raw, received ?? req.raw.url ?? '/'));
      if (out.type === 'pass') {
        applyPass(req.raw, out);
        return;
      }
      reply.code(out.status);
      const sets: string[] = [];
      for (const [n, v] of out.headers) {
        if (n.toLowerCase() === 'set-cookie') sets.push(v);
        else reply.header(n, v);
      }
      if (sets.length > 0) reply.header('set-cookie', sets);
      return reply.send(out.status === 204 ? undefined : out.body);
    });
    done();
  };
  (plugin as unknown as { [k: symbol]: boolean })[Symbol.for('skip-override')] = true;
  (plugin as unknown as { [k: symbol]: string })[Symbol.for('fastify.display-name')] =
    'revokegpt-firewall';
  return Object.assign(plugin, { firewall });
}
