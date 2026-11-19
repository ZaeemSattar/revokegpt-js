import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  createFirewall,
  type Firewall,
  type FirewallConfig,
  type FwRequest,
  type FwResult,
} from '@revokegpt/firewall';

export type { Firewall, FwRequest, FwResult };

/** `integration` defaults to the adapter's own name. */
export type NodeConfig = Omit<FirewallConfig, 'integration'> & { integration?: string };

const MAX_BODY = 4096;

/** Request headers as received, in order and with duplicates (`rawHeaders` is the only lossless source). */
export function rawHeaderPairs(req: IncomingMessage): [string, string][] {
  const out: [string, string][] = [];
  const raw = req.rawHeaders;
  for (let i = 0; i + 1 < raw.length; i += 2) out.push([raw[i] as string, raw[i + 1] as string]);
  return out;
}

/** First occurrence of a name wins (like Go's `r.Cookie`); several Cookie headers are read in order. */
export function parseCookies(values: string[]): Record<string, string> {
  const out: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const line of values) {
    for (const part of line.split(';')) {
      const eq = part.indexOf('=');
      if (eq < 1) continue;
      const name = part.slice(0, eq).trim();
      if (name === '' || name in out) continue;
      out[name] = part.slice(eq + 1).trim();
    }
  }
  return out;
}

/** Reads at most 4 KiB + 1 byte; a longer body shows up as a string over 4096 chars and is refused (413). */
async function readCapped(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    const b = Buffer.isBuffer(c) ? c : Buffer.from(c as string);
    chunks.push(b);
    size += b.length;
    if (size > MAX_BODY) break;
  }
  return Buffer.concat(chunks).toString('latin1');
}

/**
 * Builds the framework-neutral request. `rawTarget` must be the target exactly as received
 * (`req.url` for node:http, `req.originalUrl` for Express). The Host header is used as sent:
 * `X-Forwarded-Host` is client-controlled and never consulted.
 */
export function toFwRequest(req: IncomingMessage, rawTarget: string): FwRequest {
  const headers = rawHeaderPairs(req);
  const cookie = headers.filter(([n]) => n.toLowerCase() === 'cookie').map(([, v]) => v);
  const host = headers.find(([n]) => n.toLowerCase() === 'host');
  return {
    method: req.method ?? 'GET',
    host: host === undefined ? '' : host[1],
    rawTarget,
    headers,
    cookies: parseCookies(cookie),
    body: () => readCapped(req),
  };
}

/** `pass`: delete the `x-rg-*` headers the client sent, then set the decision headers (origin-bound only). */
export function applyPass(req: IncomingMessage, r: Extract<FwResult, { type: 'pass' }>): void {
  // A client header named like a rule setHeader is replaced, not joined: every copy goes first.
  const drop = new Set([
    ...r.stripHeaders.map((n) => n.toLowerCase()),
    ...Object.keys(r.setHeaders).map((n) => n.toLowerCase()),
  ]);
  const kept: string[] = [];
  for (let i = 0; i + 1 < req.rawHeaders.length; i += 2) {
    const name = req.rawHeaders[i] as string;
    if (!drop.has(name.toLowerCase())) kept.push(name, req.rawHeaders[i + 1] as string);
  }
  for (const n of drop) delete req.headers[n];
  for (const [n, v] of Object.entries(r.setHeaders)) {
    kept.push(n, v);
    req.headers[n.toLowerCase()] = v;
  }
  req.rawHeaders.length = 0;
  req.rawHeaders.push(...kept);
}

/** Sends a `respond` result as is; nothing else is added. */
export function sendRespond(res: ServerResponse, r: Extract<FwResult, { type: 'respond' }>): void {
  if (res.headersSent) {
    res.end();
    return;
  }
  const flat: string[] = [];
  for (const [n, v] of r.headers) flat.push(n, v);
  if (r.status !== 204) flat.push('Content-Length', String(Buffer.byteLength(r.body)));
  res.writeHead(r.status, flat);
  res.end(r.status === 204 ? undefined : r.body);
}

export interface NodeFirewall {
  /**
   * Decides one request. `true`: it passed (its `x-rg-*` headers are already replaced) and the
   * caller continues; `false`: the response was sent. `rawTarget` defaults to `req.url`.
   */
  (req: IncomingMessage, res: ServerResponse, rawTarget?: string): Promise<boolean>;
  readonly firewall: Firewall;
}

/** The plain `node:http` adapter; Express and Fastify wrap it. */
export function revokeGPTNodeHttp(cfg: NodeConfig): NodeFirewall {
  const firewall = createFirewall({ integration: 'node-http/0.0.0', ...cfg });
  const run = async (
    req: IncomingMessage,
    res: ServerResponse,
    rawTarget?: string,
  ): Promise<boolean> => {
    const out = await firewall.handle(toFwRequest(req, rawTarget ?? req.url ?? '/'));
    if (out.type === 'pass') {
      applyPass(req, out);
      return true;
    }
    sendRespond(res, out);
    return false;
  };
  return Object.assign(run, { firewall });
}
