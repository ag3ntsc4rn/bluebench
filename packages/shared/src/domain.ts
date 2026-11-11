const LABEL = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?$/;
const TLD = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;

/**
 * Normalize a hostname to lowercase ASCII (punycode), without a trailing dot.
 * Returns null if it isn't a plausible public DNS name (needs at least two labels and an alphabetic TLD).
 */
export function normalizeDomain(input: string): string | null {
  let host = input.trim().toLowerCase().replace(/\.$/, "");
  if (!host || host.length > 253) return null;
  if (/[^\x00-\x7f]/.test(host)) {
    // Internationalized name: let the URL parser apply IDNA/punycode.
    if (/[\s/?#@:[\]\\%]/.test(host)) return null;
    try {
      host = new URL(`http://${host}`).hostname;
    } catch {
      return null;
    }
  }
  const labels = host.split(".");
  if (labels.length < 2) return null;
  if (!TLD.test(labels.at(-1)!)) return null;
  return labels.every((l) => LABEL.test(l)) ? host : null;
}

// Common multi-label public suffixes. A heuristic, not the full Public Suffix List.
const MULTI_LABEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.nz", "org.nz", "net.nz", "govt.nz",
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
  "co.in", "net.in", "org.in", "gov.in", "ac.in",
  "co.za", "org.za", "gov.za",
  "com.br", "net.br", "org.br", "gov.br",
  "com.cn", "net.cn", "org.cn", "gov.cn",
  "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw", "com.my", "com.ph",
  "co.kr", "or.kr", "co.il", "org.il", "co.id", "or.id", "co.th", "in.th",
]);

/**
 * Shared-hosting and SaaS-tenant suffixes: anyone can get a name under these, so "victim.github.io" and
 * "evil.github.io" are different organisations. Curated from the Public Suffix List's private section
 * (the platforms phishing actually uses), plus tenant domains the list leaves out (onmicrosoft.com,
 * sharepoint.com, …). Not the full list: that would add ~42 KB to every page for a long tail of rare hosts.
 */
export const SHARED_HOSTING_SUFFIXES: ReadonlySet<string> = new Set([
  // Static hosting and app platforms
  "github.io", "gitlab.io", "pages.dev", "workers.dev", "r2.dev", "netlify.app", "vercel.app", "herokuapp.com",
  "firebaseapp.com", "firebaseio.com", "web.app", "appspot.com", "glitch.me", "repl.co", "replit.app", "onrender.com",
  "fly.dev", "up.railway.app", "ondigitalocean.app", "pythonanywhere.com", "surge.sh", "neocities.org", "csb.app",
  "app.github.dev", "amplifyapp.com", "000webhostapp.com",
  // Site builders and blogs
  "blogspot.com", "wordpress.com", "wixsite.com", "weebly.com", "square.site", "myshopify.com", "webflow.io",
  "carrd.co", "notion.site", "framer.website", "godaddysites.com", "mystrikingly.com",
  // Cloud storage and CDNs
  "azurewebsites.net", "azurestaticapps.net", "cloudapp.net", "blob.core.windows.net", "web.core.windows.net",
  "cloudfront.net", "s3.amazonaws.com",
  // Tunnels and dynamic DNS
  "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "loca.lt", "serveo.net", "duckdns.org", "ddns.net",
  "hopto.org", "zapto.org", "translate.goog",
  // SaaS tenants (each subdomain is a different customer)
  "onmicrosoft.com", "sharepoint.com", "my.salesforce.com", "force.com", "atlassian.net", "zendesk.com", "freshdesk.com",
]);

/**
 * Approximate organizational (registrable) domain: one label below the longest known suffix. Used for
 * alignment checks in the header analyzer, lookalike generation and the self-zone check. A heuristic, not
 * the full Public Suffix List; DMARC policy discovery uses RFC 9989's DNS tree walk instead.
 */
export function orgDomain(domain: string): string {
  const labels = domain.toLowerCase().replace(/\.$/, "").split(".");
  for (let k = Math.min(labels.length - 1, 4); k >= 2; k--) {
    const suffix = labels.slice(-k).join(".");
    if (SHARED_HOSTING_SUFFIXES.has(suffix) || MULTI_LABEL_SUFFIXES.has(suffix)) return labels.slice(-(k + 1)).join(".");
  }
  return labels.slice(-2).join(".");
}

/** Top-level names reserved by RFC 2606, RFC 6761 and RFC 6762, plus ICANN's private-use .internal. */
const RESERVED_TLDS = new Set(["test", "example", "invalid", "localhost", "local", "internal"]);
/** Second-level names reserved for documentation (RFC 2606) and home networks (RFC 8375). */
const RESERVED_NAMES = ["example.com", "example.net", "example.org", "home.arpa"];

/**
 * Names reserved for documentation, testing or private networks (example.com, *.test, *.local…).
 * They can never be someone's phishing site, so the browser doesn't spend a reputation lookup on
 * them: example.com in particular is in URLhaus as a host, because people submit sample links.
 */
export function isReservedDomain(host: string): boolean {
  const d = host.toLowerCase().replace(/\.$/, "");
  if (RESERVED_TLDS.has(d.slice(d.lastIndexOf(".") + 1))) return true;
  return RESERVED_NAMES.some((n) => d === n || d.endsWith(`.${n}`));
}

/** True for a domain or URL whose host is reserved (see `isReservedDomain`). */
export function isReservedIndicator(kind: string, value: string): boolean {
  if (kind === "domain") return isReservedDomain(value);
  if (kind !== "url") return false;
  try {
    return isReservedDomain(new URL(value).hostname);
  } catch {
    return false;
  }
}
