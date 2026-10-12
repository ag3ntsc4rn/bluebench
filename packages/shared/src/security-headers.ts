/**
 * Security headers sent on every response, both from the API (Hono middleware)
 * and for static assets (emitted as a `_headers` file at build time).
 * Keep this the single source of truth.
 */

/** Cloudflare Turnstile: its script and challenge iframe load from here, only when a lookup needs a challenge. */
export const TURNSTILE_ORIGIN = "https://challenges.cloudflare.com";

/** AlienVault OTX: the browser calls it directly with the user's own key (bring-your-own-key lookups). */
export const OTX_ORIGIN = "https://otx.alienvault.com";

export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  `script-src 'self' ${TURNSTILE_ORIGIN}`,
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  `connect-src 'self' ${OTX_ORIGIN}`,
  "manifest-src 'self'",
  "worker-src 'self'",
  `frame-src ${TURNSTILE_ORIGIN}`,
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "upgrade-insecure-requests",
].join("; ");

export const PERMISSIONS_POLICY = [
  "accelerometer=()",
  "camera=()",
  "geolocation=()",
  "gyroscope=()",
  "magnetometer=()",
  "microphone=()",
  "payment=()",
  "usb=()",
  "browsing-topics=()",
].join(", ");

export const SECURITY_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  "Content-Security-Policy": CONTENT_SECURITY_POLICY,
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": PERMISSIONS_POLICY,
  "X-Frame-Options": "DENY",
  "Cross-Origin-Opener-Policy": "same-origin",
});

/** Render headers in Cloudflare's `_headers` file format, applied to every path. */
export function formatHeadersFile(headers: Readonly<Record<string, string>> = SECURITY_HEADERS): string {
  const lines = Object.entries(headers).map(([name, value]) => `  ${name}: ${value}`);
  return ["/*", ...lines, ""].join("\n");
}
