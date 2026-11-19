// Next.js 16: `proxy.ts` at the project root (or in `src/`). It runs on the Node.js runtime.
//
//   import { withRevokeGPT } from '@revokegpt/firewall-next/proxy';
//   export const proxy = withRevokeGPT({ siteKey: process.env.RG_SITE_KEY!, secretKey: process.env.RG_SECRET_KEY });
//   export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };
//
// Leave `skipProxyUrlNormalize` off (the default): Next then hands the proxy its normalised URL and keeps relative
// redirects relative. If you turn it on the adapter still unwraps `_next/data`, `.prefetch` and `.segments/` URLs.
export {
  MATCHER,
  type NextConfig,
  originOf,
  rawTargetOf,
  toFwRequest,
  type WithRevokeGPTOptions,
  withRevokeGPT,
} from './core.js';
