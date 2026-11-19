/**
 * `@revokegpt/firewall`: the runtime core every JS/TS firewall integration wraps. It is a shell
 * around the reference decision engine in `@revokegpt/protocol` (protocol v1 section 18): it
 * fetches and verifies the signed policy bundle, keeps it in a single-flight cache, reads the
 * session cookies, calls siteverify behind a circuit breaker and serves the two reserved routes.
 * A framework adapter turns its request into an `FwRequest`, calls `handle`, and either forwards
 * the request (`pass`: delete `stripHeaders`, then set `setHeaders`) or sends the `respond` result.
 */
export { Breaker } from './breaker.js';
export { BundleCache, type BundleCacheOptions } from './bundle-cache.js';
export {
  type FirewallConfig,
  type LogEvent,
  MemoryVersionStore,
  type VerifiedCache,
  type VersionStore,
} from './config.js';
export { COOKIE_CLEARANCE, COOKIE_RETURN, COOKIE_SESSION } from './cookies.js';
export { createFirewall, type Firewall } from './engine.js';
export type { FwRequest, FwResult } from './rg-routes.js';
