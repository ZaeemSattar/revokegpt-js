# @revokegpt/js

Typed browser wrapper for the RevokeGPT script. MIT licensed, zero runtime dependencies, ESM and CommonJS.

```ts
import { load, render } from '@revokegpt/js';

await load({ nonce: document.querySelector<HTMLMetaElement>('meta[name=csp-nonce]')?.content });

const widget = render(document.getElementById('captcha')!, {
  sitekey: 'rgpk_...',
  action: 'login',
  callback: (token) => console.log(token),
});

const token = await widget.execute(); // send it to your server and verify it there
widget.reset();
widget.destroy(); // idempotent
```

## API

- `load({ origin?, nonce?, hl? })` injects `<script src="<origin>/v1/api.js">` once and resolves with the loader when it is ready. It rejects with `RevokeGPTLoadError` on a script error or after 15 s, and a failed load can be retried. `hl` is the default language for widgets that set none.
- `render(element, options)` returns a `Widget` (`id`, `execute()`, `reset()`, `getResponse()`, `destroy()`). Only one dialog is open at a time: a call while one is open rejects at once with `Error('busy')`. Call it after `await load()`. `options` mirror the loader: `sitekey`, `theme` (`light | dark | auto`), `size` (`normal | compact | invisible`, default `invisible`), `tabindex`, `badge`, `hl` (one of the 28 launch locales), `action`, `cdata`, `callback`, `expired-callback`, `error-callback`, `title`, `isolated`.
- `challengeAccount(sitekey, { requestToken, container?, languageCode? })` runs the email-code step of account verification: a dialog asks for the code, and the promise resolves with the verification token (present it to an assessment of the same account; it rejects with `Error('cancelled')` when the person cancels). Call it after `await load()`.

The token is only a claim until your server verifies it with `@revokegpt/node` (or siteverify). Never trust it in the browser.

## Origin pinning

`origin` accepts a bare `https:` origin only (no path, query or credentials). `http://localhost:*` is accepted only when `process.env.NODE_ENV !== 'production'`; where there is no `process`, the page counts as production. Any other scheme (`javascript:`, `data:`, `http:`) is rejected before anything is injected. The default is `https://js.revokegpt.com`, a placeholder until the final domain is set.

## Content Security Policy

- `script-src`: allow the widget origin (`https://js.revokegpt.com`), or use a nonce: pass `nonce` to `load()`; it is set on the injected script, and the loader copies it onto everything it adds.
- `frame-src`: allow the widget origin (each widget is an iframe from it).
- `connect-src`: no entry is needed on the host page; the frame makes its own requests.
- `style-src`: the loader only sets CSSOM properties and needs no `'unsafe-inline'`.
