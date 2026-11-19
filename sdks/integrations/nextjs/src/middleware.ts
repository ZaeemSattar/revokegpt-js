// Next.js 15.5: `middleware.ts` shim over the same core. Needs `export const config = { runtime: 'nodejs', matcher: [...] }`
// in your middleware file (the Node runtime for middleware is stable from 15.5). Leave
// `skipMiddlewareUrlNormalize` off (the default); see the README.
//
//   import { withRevokeGPTMiddleware } from '@revokegpt/firewall-next/middleware';
//   export const middleware = withRevokeGPTMiddleware({ siteKey: process.env.RG_SITE_KEY! });
import { withRevokeGPT } from './core.js';

export {
  MATCHER,
  type NextConfig,
  originOf,
  rawTargetOf,
  toFwRequest,
  type WithRevokeGPTOptions,
} from './core.js';
export const withRevokeGPTMiddleware = withRevokeGPT;
