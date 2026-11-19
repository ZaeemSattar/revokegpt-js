# @revokegpt/react

React component and hook for RevokeGPT, a thin wrapper over [`@revokegpt/js`](../js-sdk). MIT licensed. Peer: `react ^18.2 || ^19`. The entry carries `"use client"`, so it works in the Next.js App Router, and it touches no `window` during a server render.

```tsx
import { RevokeGPT, type RevokeGPTHandle, useRevokeGPT } from '@revokegpt/react';

const ref = useRef<RevokeGPTHandle>(null);
<RevokeGPT ref={ref} sitekey="rgpk_..." size="normal" onVerify={(token) => send(token)} />;
const token = await ref.current?.execute(); // also: reset(), getResponse()

// An invisible widget with no markup of your own:
const { execute, ready } = useRevokeGPT({ sitekey: 'rgpk_...', action: 'login' });
const token2 = await execute('checkout'); // the action argument is optional
```

Props: `sitekey`, `theme`, `size`, `hl`, `action`, `cdata`, `tabIndex`, `badge`, `origin`, `nonce`, `className`, and the callbacks `onVerify(token)`, `onExpire()`, `onError(code)`.

- Callbacks are read through a ref, so a new `onVerify` on each render never recreates the widget. Changing `sitekey`, `size`, `theme`, `hl`, `action`, `cdata`, `tabIndex`, `badge`, `origin` or `nonce` destroys the widget and renders a new one.
- A render failure calls `onError('render-error')`.
- `execute()` calls on one hook run one at a time, so two calls with different actions both resolve.
- A script that fails to load (or a bad `origin`) calls `onError('load-error')`.
- There is no script-URL prop. `origin` takes a bare `https:` origin and is validated by `@revokegpt/js`.
- The token is only a claim until your server verifies it (`@revokegpt/node` or siteverify).
