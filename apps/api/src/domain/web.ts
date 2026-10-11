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
  /** https://domain/ chain, or why it failed. */
  https: { hops: SafeFetchHop[] } | { error: string };
  /** First response from http://domain/, or why it failed. */
  http: SafeFetchHop | { error: string };
}

function describe(e: unknown): string {
  if (e instanceof BudgetExceeded) return "budget";
  if (e instanceof BlockedUrlError) return e.message;
  if (e instanceof DOMException && e.name === "TimeoutError") return "Timed out after 5 seconds";
  return "Couldn't connect";
}

/** Fetch the site's home page over https (following up to 3 redirects) and http (first response only). */
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
    safeFetch(`https://${domain}/`, opts).then(
      async (res) => {
        await res.response.body?.cancel(); // headers are all we need
        return { hops: res.hops };
      },
      (e: unknown) => ({ error: describe(e) }),
    ),
    safeFetch(`http://${domain}/`, { ...opts, noFollow: true }).then(
      async (res) => {
        await res.response.body?.cancel();
        return res.hops[0]!;
      },
      (e: unknown) => ({ error: describe(e) }),
    ),
  ]);
  return { hasAddress, https, http };
}

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
  const facts = [fact("HTTPS response", `${final.status} from ${final.url}`)];
  if ("error" in probe.http) {
    // Port 80 closed is fine: nothing is served unencrypted.
    return { status: "pass", summary: "Loads over HTTPS, and nothing is served over plain HTTP.", facts };
  }
  const loc = probe.http.headers.get("location") ?? "";
  facts.push(fact("Plain HTTP", probe.http.status >= 300 && probe.http.status < 400 ? `${probe.http.status} → ${loc}` : String(probe.http.status)));
  let target: URL | null = null;
  try {
    target = new URL(loc, `http://${domain}/`);
  } catch {
    // ignore
  }
  if (probe.http.status >= 300 && probe.http.status < 400 && target?.protocol === "https:") {
    return { status: "pass", summary: "Loads over HTTPS, and plain HTTP redirects to it.", facts };
  }
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
  // HSTS on the first HTTPS response protects this exact host, even if it then redirects (e.g. to www).
  const header = probe.https.hops[0]!.headers.get("strict-transport-security");
  const fix = "Send Strict-Transport-Security: max-age=31536000; includeSubDomains on every HTTPS response.";
  if (!header) {
    return { status: "fail", summary: "No HSTS header, so a first visit over http:// can be intercepted.", fix, facts: [] };
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

const HEADER_CHECKS: { name: string; present: (h: Headers) => boolean }[] = [
  { name: "Content-Security-Policy", present: (h) => h.has("content-security-policy") },
  { name: "X-Content-Type-Options", present: (h) => /nosniff/i.test(h.get("x-content-type-options") ?? "") },
  {
    name: "Clickjacking protection (X-Frame-Options or frame-ancestors)",
    present: (h) => h.has("x-frame-options") || /frame-ancestors/i.test(h.get("content-security-policy") ?? ""),
  },
  { name: "Referrer-Policy", present: (h) => h.has("referrer-policy") },
  { name: "Permissions-Policy", present: (h) => h.has("permissions-policy") },
];

export function headersCheck(probe: WebProbe): Check {
  if (!probe.hasAddress) return NO_SITE;
  if ("error" in probe.https) return { status: "skipped", summary: "Skipped: the site doesn't load over HTTPS.", facts: [] };
  const final = probe.https.hops.at(-1)!;
  const missing = HEADER_CHECKS.filter((c) => !c.present(final.headers)).map((c) => c.name);
  const have = HEADER_CHECKS.length - missing.length;
  const facts = HEADER_CHECKS.map((c) => fact(c.name, missing.includes(c.name) ? "missing" : "present"));
  if (missing.length === 0) return { status: "pass", summary: "All five recommended security headers are set.", facts };
  const fix = `Add ${missing.join(", ")} at your web server or CDN.`;
  if (have >= 3) return { status: "warn", summary: `${have} of 5 recommended security headers are set.`, fix, facts };
  return { status: "fail", summary: `Only ${have} of 5 recommended security headers are set.`, fix, facts };
}
