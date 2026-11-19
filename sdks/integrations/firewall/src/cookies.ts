export const COOKIE_SESSION = '__Host-rg_s';
export const COOKIE_CLEARANCE = '__Host-rg_c';
export const COOKIE_RETURN = '__Host-rg_r';

const MAX_COOKIE_BYTES = 4096;
/** RFC 6265 cookie-octets: printable ASCII except space, `"`, `,`, `;` and `\`. */
const COOKIE_VALUE = /^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*$/;
const ATTRS = 'Path=/; Secure; HttpOnly; SameSite=Lax';

/** True if `v` can be sent as a cookie value as is (the return path is stored unencoded). */
export const isCookieSafe = (v: string): boolean => COOKIE_VALUE.test(v);

/** `__Host-` cookie: `Max-Age`, then `Path=/; Secure; HttpOnly; SameSite=Lax`. Null if it would not fit or is unsafe. */
export function setCookie(name: string, value: string, maxAgeSeconds: number): string | null {
  if (!isCookieSafe(value) || !Number.isInteger(maxAgeSeconds) || maxAgeSeconds < 0) return null;
  const c = `${name}=${value}; Max-Age=${maxAgeSeconds}; ${ATTRS}`;
  return c.length > MAX_COOKIE_BYTES ? null : c;
}

export const clearCookie = (name: string): string => `${name}=; Max-Age=0; ${ATTRS}`;
