import { base64ToBytes } from "./encoding.ts";

/**
 * Link-protection wrappers: email security gateways rewrite every link in a message to point at
 * their own servers, so a link copied from a reported email is usually the wrapper, not the site.
 * Checking the wrapper's reputation, or flagging its many subdomains, tells the analyst nothing.
 *
 * - Microsoft Defender Safe Links: https://nam12.safelinks.protection.outlook.com/?url=<encoded>&data=…
 * - Proofpoint URL Defense v1/v2: https://urldefense.proofpoint.com/v2/url?u=<encoded>&d=…
 * - Proofpoint URL Defense v3: https://urldefense.com/v3/__<url>__;<base64>!!…
 * - Mimecast URL Protect: https://protect-eu.mimecast.com/s/<token>?domain=example.com. The token is
 *   resolved on Mimecast's servers, so only the destination's domain can be recovered.
 *
 * Pure: the original link is decoded from the wrapper itself, never fetched.
 */

export type LinkWrapper = "Microsoft Safe Links" | "Proofpoint URL Defense" | "Mimecast";

export interface UnwrappedLink {
  wrapper: LinkWrapper;
  /** The original link, or null when the wrapper doesn't contain it (Mimecast). */
  url: string | null;
  /** The original link's host. */
  host: string;
}

/** Wrappers wrapped in wrappers (a forwarded message, two gateways) are peeled up to this depth. */
const MAX_DEPTH = 3;

function asHttpUrl(s: string | null | undefined): URL | null {
  if (!s) return null;
  try {
    const url = new URL(s.trim());
    return (url.protocol === "http:" || url.protocol === "https:") && url.hostname ? url : null;
  } catch {
    return null;
  }
}

/** Proofpoint v3 run lengths: "**A" is 2 characters, "**B" 3, … "**_" 65. */
const V3_RUNS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function base64UrlToText(s: string): string | null {
  const bytes = base64ToBytes(s);
  if (!bytes) return null;
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    return null;
  }
}

/**
 * Proofpoint v3 keeps the URL readable but swaps some characters for "*" (one character) or
 * "**X" (a run whose length X encodes); the missing characters follow "__;" as URL-safe base64.
 */
function proofpointV3(href: string): string | null {
  const m = /\/v3\/__(.+?)__;([A-Za-z0-9_-]*)!/.exec(href);
  if (!m) return null;
  const chars = [...(base64UrlToText(m[2]!) ?? "")];
  let pos = 0;
  let ok = true;
  const url = m[1]!.replace(/\*(\*.)?/g, (token, run?: string) => {
    const len = run ? V3_RUNS.indexOf(run[1]!) + 2 : 1;
    if (len < 1 || (run && len < 2) || pos + len > chars.length) {
      ok = false;
      return token;
    }
    const out = chars.slice(pos, pos + len).join("");
    pos += len;
    return out;
  });
  return ok ? url : null;
}

function unwrapOnce(url: URL): UnwrappedLink | null {
  const host = url.hostname.toLowerCase();

  if (/(?:^|\.)safelinks\.protection\.(?:outlook\.com|office365\.us)$/.test(host)) {
    const inner = asHttpUrl(url.searchParams.get("url"));
    return inner && { wrapper: "Microsoft Safe Links", url: inner.href, host: inner.hostname };
  }

  if (host === "urldefense.proofpoint.com") {
    const u = url.searchParams.get("u");
    if (!u) return null;
    let decoded: string | null = u;
    if (url.pathname.startsWith("/v2/")) {
      try {
        decoded = decodeURIComponent(u.replace(/-/g, "%").replace(/_/g, "/"));
      } catch {
        decoded = null;
      }
    }
    const inner = asHttpUrl(decoded);
    return inner && { wrapper: "Proofpoint URL Defense", url: inner.href, host: inner.hostname };
  }

  if ((host === "urldefense.com" || host === "urldefense.us") && url.pathname.startsWith("/v3/")) {
    const inner = asHttpUrl(proofpointV3(url.href));
    return inner && { wrapper: "Proofpoint URL Defense", url: inner.href, host: inner.hostname };
  }

  if (/(?:^|\.)mimecast(?:protect)?\.com$/.test(host) && /^\/s\//.test(url.pathname)) {
    const domain = asHttpUrl(`https://${url.searchParams.get("domain") ?? ""}`)?.hostname;
    return domain ? { wrapper: "Mimecast", url: null, host: domain } : null;
  }

  return null;
}

/**
 * The link inside a Safe Links, Proofpoint or Mimecast wrapper; null if `href` isn't a wrapper
 * (or is one we can't decode). The wrapper named is the outermost one.
 */
export function unwrapLink(href: string): UnwrappedLink | null {
  let url = asHttpUrl(href);
  if (!url) return null;
  let result = null as UnwrappedLink | null;
  for (let depth = 0; depth < MAX_DEPTH; depth++) {
    const next = unwrapOnce(url);
    if (!next) break;
    result = { ...next, wrapper: result?.wrapper ?? next.wrapper };
    if (!next.url) break;
    url = new URL(next.url);
  }
  return result;
}
