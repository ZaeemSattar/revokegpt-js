import {
  type Badge,
  type Locale,
  load,
  render,
  type Size,
  type Theme,
  type Widget,
} from '@revokegpt/js';
import { defineComponent, h, onBeforeUnmount, onMounted, type PropType, ref, watch } from 'vue';

/**
 * Ruling: a render-function component in .ts, not an SFC. An SFC would need @vitejs/plugin-vue, a
 * vite library build and vue-tsc for the declarations, a heavy toolchain for a one-element
 * component; plain tsc builds this one.
 */
export const RevokeGPT = defineComponent({
  name: 'RevokeGPT',
  props: {
    sitekey: { type: String, required: true },
    theme: String as PropType<Theme>,
    size: String as PropType<Size>,
    hl: String as PropType<Locale>,
    action: String,
    cdata: String,
    tabIndex: Number,
    badge: String as PropType<Badge>,
    /** A widget origin, validated by `@revokegpt/js` (`https:` only). There is no script-URL prop. */
    origin: String,
    nonce: String,
    /** v-model: the live token, '' when there is none. */
    modelValue: { type: String, default: '' },
  },
  emits: {
    verify: (_token: string) => true,
    expire: () => true,
    error: (_code: string) => true,
    'update:modelValue': (_token: string) => true,
  },
  setup(props, { emit, expose }) {
    const host = ref<HTMLElement | null>(null);
    let widget: Widget | undefined;
    let generation = 0;
    let token = '';
    const clearToken = (): void => {
      if (token === '') return;
      token = '';
      emit('update:modelValue', '');
    };

    function mount(): void {
      const el = host.value;
      if (el === null) return;
      const mine = ++generation;
      const { origin, nonce, hl } = props;
      load({
        ...(origin !== undefined && { origin }),
        ...(nonce !== undefined && { nonce }),
        ...(hl !== undefined && { hl }),
      }).then(
        () => {
          if (mine !== generation) return; // unmounted or superseded before load resolved
          const p = props;
          try {
            widget = render(el, {
              sitekey: p.sitekey,
              ...(p.theme !== undefined && { theme: p.theme }),
              ...(p.size !== undefined && { size: p.size }),
              ...(p.hl !== undefined && { hl: p.hl }),
              ...(p.action !== undefined && { action: p.action }),
              ...(p.cdata !== undefined && { cdata: p.cdata }),
              ...(p.tabIndex !== undefined && { tabindex: p.tabIndex }),
              ...(p.badge !== undefined && { badge: p.badge }),
              callback: (t) => {
                token = t;
                emit('update:modelValue', t);
                emit('verify', t);
              },
              'expired-callback': () => {
                clearToken();
                emit('expire');
              },
              'error-callback': (code) => emit('error', code),
            });
          } catch {
            emit('error', 'render-error');
          }
        },
        () => {
          if (mine === generation) emit('error', 'load-error');
        },
      );
    }

    function unmount(): void {
      generation++;
      clearToken();
      widget?.destroy();
      widget = undefined;
    }

    onMounted(mount);
    onBeforeUnmount(unmount);
    // Props that need a new widget destroy the old one and render a new one.
    watch(
      () => [
        props.sitekey,
        props.theme,
        props.size,
        props.hl,
        props.action,
        props.cdata,
        props.tabIndex,
        props.badge,
        props.origin,
        props.nonce,
      ],
      () => {
        unmount();
        mount();
      },
    );

    expose({
      execute: (): Promise<string> =>
        widget?.execute() ?? Promise.reject(new Error('widget is not ready')),
      reset: (): void => {
        widget?.reset();
        clearToken();
      },
      getResponse: (): string => widget?.getResponse() ?? '',
    });

    return () => h('div', { ref: host });
  },
});

export interface RevokeGPTExposed {
  execute(): Promise<string>;
  reset(): void;
  getResponse(): string;
}
