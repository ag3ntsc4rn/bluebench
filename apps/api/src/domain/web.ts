import type { DomainCheck } from "@bluebench/shared";
import { Budget, BudgetExceeded, type Resolver } from "../dns.ts";
import { BlockedUrlError, safeFetch, type SafeFetchHop } from "../safe-fetch.ts";

type Check = Omit<DomainCheck, "id">;
const fact = (label: string, value: string) => ({ label, value });

/** Identifies our requests to the sites we check, with a page explaining them. */
export const USER_AGENT = "Mozilla/5.0 (compatible; Bluebench/1.0; +https://bluebench.dev/privacy)";
const ONE_YEAR = 31_536_000;

export interface WebProbe {
  /** False when the name has no A/AAAA records: there's no website to grade. */
  hasAddress: boolean;
  /** https://domain/ chain (possibly cut off at the redirect cap), or why it failed. */
  https: { hops: SafeFetchHop[]; redirectLimitHit: boolean } | { error: string };
  /** Where plain http://domain/ leads, or why it failed. */
  http: PlainHttp | { error: string };
}

export interface PlainHttp {
  /** The plain-HTTP chain ends in a redirect to an https:// URL. */
  reachesHttps: boolean;
  /** e.g. "301 → /mail/, 301 → https://example.com/mail/" or "200". */
  trail: string;
}

const isRedirect = (status: number) => status >= 300 && status < 400;

/**
 * Follow plain-HTTP redirects (up to 3, each SSRF-checked) until one points at https://. We stop there,
 * without fetching the https:// URL: the HTTPS probe covers that.
 */
async function followPlainHttp(start: string, opts: Parameters<typeof safeFetch>[1]): Promise<PlainHttp> {
  let url = start;
  const trail: string[] = [];
  for (let hop = 0; hop < 3; hop++) {
    const res = await safeFetch(url, { ...opts, noFollow: true });
    await res.response.body?.cancel();
    const { status, headers } = res.hops[0]!;
    const location = headers.get("location");
    if (!isRedirect(status) || !location) {
      trail.push(String(status));
      return { reachesHttps: false, trail: trail.join(", ") };
    }
    trail.push(`${status} → ${location}`);
    let next: URL;
    try {
      next = new URL(location, url);
    } catch {
      return { reachesHttps: false, trail: trail.join(", ") };
    }
    if (next.protocol === "https:") return { reachesHttps: true, trail: trail.join(", ") };
    url = next.href;
  }
  return { reachesHttps: false, trail: `${trail.join(", ")}, …` };
}

function describe(e: unknown): string {
  if (e instanceof BudgetExceeded) return "budget";
  if (e instanceof BlockedUrlError) return e.message;
  if (e instanceof DOMException && e.name === "TimeoutError") return "Timed out after 5 seconds";
  return "Couldn't connect";
}

/** Fetch the site's home page over https (up to 3 redirects) and see where plain http leads (up to 3 redirects). */
export async function probeWeb(r: Resolver, budget: Budget, domain: string): Promise<WebProbe> {
  const hasAddress = (await r.addresses(domain)).length > 0;
  if (!hasAddress) return { hasAddress, https: { error: "No address" }, http: { error: "No address" } };
  const opts = {
    resolve: (host: string) => r.addresses(host),
    beforeFetch: () => {
      if (!budget.take()) throw new BudgetExceeded();
    },
    headers: { "user-agent": USER_AGENT, accept: "text/html" },
  };
  const [https, http] = await Promise.all([
    safeFetch(`https://${domain}/`, { ...opts, returnAtRedirectLimit: true }).then(
      async (res) => {
        await res.response.body?.cancel(); // headers are all we need
        return { hops: res.hops, redirectLimitHit: res.redirectLimitHit === true };
      },
      (e: unknown) => ({ error: describe(e) }),
    ),
    followPlainHttp(`http://${domain}/`, opts).catch((e: unknown) => ({ error: describe(e) })),
  ]);
  return { hasAddress, https, http };
}

/** A 5xx anywhere in the HTTPS chain means we got an error page (e.g. Cloudflare's 522), not the site. */
const serverError = (probe: WebProbe): number | null => {
  if ("error" in probe.https) return null;
  const bad = probe.https.hops.find((h) => h.status >= 500);
  return bad ? bad.status : null;
};
const ERROR_PAGE = (status: number): Check => ({
  status: "skipped",
  summary: `Skipped: the site answered with a server error (${status}), so its headers aren't the site's.`,
  facts: [],
});

const NO_SITE: Check = { status: "info", summary: "No website at this domain, so there's nothing to check.", facts: [] };
const skipped = (why: string): Check => ({ status: "skipped", summary: `Couldn't check this time (${why}).`, facts: [] });

export function httpsCheck(probe: WebProbe, domain: string): Check {
  if (!probe.hasAddress) return NO_SITE;
  if ("error" in probe.https) {
    if (probe.https.error === "budget") return skipped("request budget used up");
    return {
      status: "fail",
      summary: `The site doesn't load over HTTPS (${probe.https.error.toLowerCase()}).`,
      fix: "Serve the site over HTTPS with a valid certificate (free from Let's Encrypt or your host).",
      facts: [],
    };
  }
  const final = probe.https.hops.at(-1)!;
  const error = serverError(probe);
  if (error) {
    return {
      status: "fail",
      summary: `The site answered over HTTPS with a server error (${error}), so it isn't loading.`,
      fix: "Check the web server or hosting is up and reachable; a 52x code means the CDN can't reach the origin server.",
      facts: [fact("HTTPS response", `${error} from ${final.url}`)],
    };
  }
  const facts = [
    fact("HTTPS response", probe.https.redirectLimitHit ? `stopped after ${probe.https.hops.length} redirects` : `${final.status} from ${final.url}`),
  ];
  if ("error" in probe.http) {
    // Port 80 closed is fine: nothing is served unencrypted.
    return { status: "pass", summary: "Loads over HTTPS, and nothing is served over plain HTTP.", facts };
  }
  facts.push(fact("Plain HTTP", probe.http.trail));
  if (probe.http.reachesHttps) return { status: "pass", summary: "Loads over HTTPS, and plain HTTP redirects to it.", facts };
  return {
    status: "warn",
    summary: "Loads over HTTPS, but plain HTTP doesn't redirect to it, so some visitors stay unencrypted.",
    fix: "Redirect every http:// request to https:// (a 301 at your web server or CDN).",
    facts,
  };
}

export function parseHsts(header: string): { maxAge: number; includeSubDomains: boolean; preload: boolean } {
  const maxAge = /max-age\s*=\s*"?(\d+)"?/i.exec(header);
  return {
    maxAge: maxAge ? Number(maxAge[1]) : 0,
    includeSubDomains: /(^|;)\s*includeSubDomains\s*(;|$)/i.test(header),
    preload: /(^|;)\s*preload\s*(;|$)/i.test(header),
  };
}

export function hstsCheck(probe: WebProbe): Check {
  if (!probe.hasAddress) return NO_SITE;
  if ("error" in probe.https) return { status: "skipped", summary: "Skipped: the site doesn't load over HTTPS.", facts: [] };
  const errorHsts = serverError(probe);
  if (errorHsts) return ERROR_PAGE(errorHsts);
  // HSTS on the first HTTPS response protects this exact host, even if it then redirects (e.g. to www).
  const header = probe.https.hops[0]!.headers.get("strict-transport-security");
  const fix = "Send Strict-Transport-Security: max-age=31536000; includeSubDomains on every HTTPS response.";
  if (!header) {
    return {
      status: "fail",
      summary: "No HSTS header, so a first visit over http:// can be intercepted (unless browsers have the domain preloaded).",
      fix,
      facts: [],
    };
  }
  const h = parseHsts(header);
  const facts = [fact("Header", header)];
  if (h.maxAge < ONE_YEAR) {
    const days = Math.floor(h.maxAge / 86_400);
    return {
      status: "warn",
      summary: `HSTS is on, but only for ${days === 0 ? "less than a day" : `${days} day${days === 1 ? "" : "s"}`}.`,
      fix: "Raise max-age to at least 31536000 (one year).",
      facts,
    };
  }
  const extras = [h.includeSubDomains && "includes subdomains", h.preload && "preload-ready"].filter(Boolean).join(", ");
  return { status: "pass", summary: `HSTS is on for a year or more${extras ? ` (${extras})` : ""}.`, facts };
}

/** `label` is the short form shown in the facts list; `name` is used in the fix text. */
const HEADER_CHECKS: { label: string; name: string; present: (h: Headers) => boolean }[] = [
  { label: "CSP", name: "Content-Security-Policy", present: (h) => h.has("content-security-policy") },
  { label: "nosniff", name: "X-Content-Type-Options: nosniff", present: (h) => /nosniff/i.test(h.get("x-content-type-options") ?? "") },
  {
    label: "Framing",
    name: "clickjacking protection (X-Frame-Options or CSP frame-ancestors)",
    present: (h) => h.has("x-frame-options") || /frame-ancestors/i.test(h.get("content-security-policy") ?? ""),
  },
  { label: "Referrer-Policy", name: "Referrer-Policy", present: (h) => h.has("referrer-policy") },
  { label: "Permissions-Policy", name: "Permissions-Policy", present: (h) => h.has("permissions-policy") },
];

export function headersCheck(probe: WebProbe): Check {
  if (!probe.hasAddress) return NO_SITE;
  if ("error" in probe.https) return { status: "skipped", summary: "Skipped: the site doesn't load over HTTPS.", facts: [] };
  const error = serverError(probe);
  if (error) return ERROR_PAGE(error);
  if (probe.https.redirectLimitHit) {
    // Headers on a redirect aren't the page's headers; we don't follow further to find the page.
    return { status: "skipped", summary: "Skipped: the home page redirects more than 3 times, and we stop there.", facts: [] };
  }
  const final = probe.https.hops.at(-1)!;
  const missing = HEADER_CHECKS.filter((c) => !c.present(final.headers)).map((c) => c.name);
  const have = HEADER_CHECKS.length - missing.length;
  const facts = HEADER_CHECKS.map((c) => fact(c.label, missing.includes(c.name) ? "missing" : "present"));
  if (missing.length === 0) return { status: "pass", summary: "All five recommended security headers are set.", facts };
  const fix = `Add ${missing.join(", ")} at your web server or CDN.`;
  if (have >= 3) return { status: "warn", summary: `${have} of 5 recommended security headers are set.`, fix, facts };
  return { status: "fail", summary: `Only ${have} of 5 recommended security headers are set.`, fix, facts };
}
