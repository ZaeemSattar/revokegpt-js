// Runs the Worker locally with `wrangler dev`, mapping the conformance env contract
// (tools/policy-conformance/README.md) onto Worker vars. Usage: PORT=4812 RG_ORIGIN=... node example/serve.mjs
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const names = [
  'RG_API_BASE',
  'RG_SITE_KEY',
  'RG_SECRET_KEY',
  'RG_ORIGIN',
  'RG_BUNDLE_REFRESH_MS',
  'RG_PIN_TEST_KEYS',
];
const args = ['dev', '--config', fileURLToPath(new URL('./wrangler.jsonc', import.meta.url))];
args.push(
  '--ip',
  '127.0.0.1',
  '--port',
  process.env.PORT ?? '8787',
  '--show-interactive-dev-session=false',
);
for (const n of names) {
  const v = process.env[n];
  if (v !== undefined && v !== '') args.push('--var', `${n}:${v}`);
}
const child = spawn(
  process.execPath,
  [fileURLToPath(new URL('../node_modules/wrangler/bin/wrangler.js', import.meta.url)), ...args],
  { stdio: 'inherit' },
);
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => child.kill(s));
child.on('exit', (code) => process.exit(code ?? 0));
