# @revokegpt/vue

Vue 3 component and composable for RevokeGPT, a thin wrapper over [`@revokegpt/js`](../js-sdk). MIT licensed. Peer: `vue ^3.4`. It is a render-function component (no SFC build step needed), and it touches no `window` during a server render.

```vue
<script setup lang="ts">
import { ref } from 'vue';
import { RevokeGPT, useRevokeGPT } from '@revokegpt/vue';

const token = ref('');
const captcha = ref<InstanceType<typeof RevokeGPT>>();
</script>

<template>
  <RevokeGPT ref="captcha" v-model="token" sitekey="rgpk_..." size="normal" @error="onError" />
  <!-- also emits verify(token) and expire(); exposes execute(), reset(), getResponse() -->
</template>
```

```ts
const { execute, ready } = useRevokeGPT({ sitekey: 'rgpk_...', action: 'login' }); // in setup()
const token = await execute('checkout'); // the action argument is optional
```

Props: `sitekey`, `theme`, `size`, `hl`, `action`, `cdata`, `tabIndex`, `badge`, `origin`, `nonce`, `modelValue`.

- `v-model` holds the live token and is cleared to `''` on expiry.
- Changing `sitekey`, `size`, `theme`, `hl`, `action`, `cdata`, `tabIndex`, `badge`, `origin` or `nonce` destroys the widget and renders a new one. The widget is destroyed on unmount.
- A render failure (for example a container that already holds a widget) emits `error` with `render-error`.
- A script that fails to load (or a bad `origin`) emits `error` with `load-error`.
- There is no script-URL prop. `origin` takes a bare `https:` origin and is validated by `@revokegpt/js`.
- The token is only a claim until your server verifies it (`@revokegpt/node` or siteverify).

## Nuxt and SSR

The widget only exists in the browser. In Nuxt, wrap it so it is not rendered on the server:

```vue
<ClientOnly>
  <RevokeGPT v-model="token" sitekey="rgpk_..." />
</ClientOnly>
```

`useRevokeGPT` must be called in `setup()` of a component. It touches the DOM only after mount, so it is safe to call during SSR, but `execute()` rejects until the widget is ready.
