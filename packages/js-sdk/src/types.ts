/** The 28 launch locales of the widget. */
export type Locale =
  | 'en'
  | 'es'
  | 'fr'
  | 'de'
  | 'it'
  | 'pt-BR'
  | 'pt-PT'
  | 'nl'
  | 'pl'
  | 'ru'
  | 'uk'
  | 'tr'
  | 'ar'
  | 'he'
  | 'fa'
  | 'hi'
  | 'bn'
  | 'id'
  | 'ms'
  | 'vi'
  | 'th'
  | 'ja'
  | 'ko'
  | 'zh-CN'
  | 'zh-TW'
  | 'sv'
  | 'cs'
  | 'el';

export type Theme = 'light' | 'dark' | 'auto';
/** `normal` and `compact` are the checkbox frame; `invisible` is a hidden frame plus a badge. */
export type Size = 'normal' | 'compact' | 'invisible';
export type Badge = 'bottomright' | 'bottomleft' | 'inline';

export interface RenderOptions {
  /** The site key (`rgpk_` plus 20 letters or digits). */
  sitekey: string;
  theme?: Theme;
  /** Default `invisible`. */
  size?: Size;
  tabindex?: number;
  /** Invisible size only. Default `bottomright`. */
  badge?: Badge;
  /** The widget language. Defaults to the `hl` given to `load()`. */
  hl?: Locale;
  action?: string;
  cdata?: string;
  /** Receives the response token. */
  callback?: (token: string) => void;
  /** The token expired and was dropped. */
  'expired-callback'?: () => void;
  /** Receives the error code (for example `network-error`). */
  'error-callback'?: (code: string) => void;
  title?: string;
  /** The name of the hidden response field. Default `revokegpt-response`. */
  responseField?: 'revokegpt-response' | 'g-recaptcha-response';
  /** The widget has no part in the default widget rule of the loader. */
  isolated?: boolean;
  /**
   * Keep a firewall session (M9): the loader runs a hidden `rg_session` widget at load and again 300 s
   * before each session token expires while the tab is visible, and hands the token to the site's
   * integration (POST `/__rg/session`) or, when none answers, sets the `__Host-rg_s` cookie. Default false.
   */
  session?: boolean;
}

export interface ChallengeAccountOptions {
  /** The `requestToken` of an assessment's `accountVerification.endpoints` entry. */
  requestToken: string;
  /** Holds the temporary response field of the dialog's hidden widget. Default: the body. */
  container?: Element | string;
  /** The dialog language. Defaults to the `hl` given to `load()`. */
  languageCode?: Locale;
}

export interface LoadOptions {
  /** A widget origin: `https:` only (or `http://localhost:*` outside production). */
  origin?: string;
  /** Copied onto the injected script as its CSP nonce. */
  nonce?: string;
  /** The default `hl` for widgets rendered through this package. */
  hl?: Locale;
}

/** The native loader global, `window.revokegpt`. */
export interface RevokeGPTApi {
  render(container: Element | string, params: RenderOptions): number;
  execute(widgetId?: number): Promise<string>;
  reset(widgetId?: number): void;
  getResponse(widgetId?: number): string;
  ready(fn: () => void): void;
  remove(widgetId: number): void;
  /** Rejects with `Error('cancelled')` on cancel and `Error('busy')` while another dialog is open. */
  challengeAccount(sitekey: string, params: ChallengeAccountOptions): Promise<string>;
}

export interface Widget {
  readonly id: number;
  /** Runs the challenge and resolves with the response token. */
  execute(): Promise<string>;
  reset(): void;
  /** The live token, or '' when there is none. */
  getResponse(): string;
  /** Removes the widget. Safe to call more than once. */
  destroy(): void;
}
