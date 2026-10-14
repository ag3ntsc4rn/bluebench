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
  /**
   * Where plain http://domain/ leads, or why it failed. `closed` is true only when the connection itself
   * failed (nothing listening); a timeout, the budget or a blocked hop tell us nothing about port 80.
   */
  http: PlainHttp | { error: string; closed: boolean };
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
  if (!hasAddress) return { hasAddress, https: { error: "No address" }, http: { error: "No address", closed: false } };
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
    // fetch() rejects with a TypeError when it can't connect at all; anything else leaves port 80 unknown.
    followPlainHttp(`http://${domain}/`, opts).catch((e: unknown) => ({ error: describe(e), closed: e instanceof TypeError })),
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
    // Port 80 closed is fine: nothing is served unencrypted. Anything else is no evidence either way.
    if (probe.http.closed) return { status: "pass", summary: "Loads over HTTPS, and nothing is served over plain HTTP.", facts };
    const why = probe.http.error === "budget" ? "request budget used up" : probe.http.error.toLowerCase();
    return {
      status: "skipped",
      summary: `Loads over HTTPS, but we couldn't tell whether plain HTTP redirects to it (${why}), so this isn't graded this time.`,
      facts,
    };
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

export type Hsts = { valid: true; maxAge: number; includeSubDomains: boolean; preload: boolean } | { valid: false; why: string };

/**
 * Parse a whole Strict-Transport-Security value (RFC 6797 §6.1). Browsers ignore a header that repeats a
 * directive, lacks max-age or has a malformed one, so those come back invalid. Unknown directives are allowed.
 */
export function parseHsts(header: string): Hsts {
  const seen = new Map<string, string | undefined>();
  for (const part of header.split(";")) {
    const directive = part.trim();
    if (!directive) continue;
    const eq = directive.indexOf("=");
    const name = (eq < 0 ? directive : directive.slice(0, eq)).trim().toLowerCase();
    if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(name)) return { valid: false, why: `"${directive}" isn't a valid directive` };
    if (seen.has(name)) return { valid: false, why: `${name} appears more than once` };
    seen.set(name, eq < 0 ? undefined : directive.slice(eq + 1).trim());
  }
  const raw = seen.get("max-age");
  const m = raw === undefined ? null : /^(?:(\d+)|"(\d+)")$/.exec(raw);
  if (!m) return { valid: false, why: raw === undefined ? "max-age is missing" : `max-age=${raw} isn't a number` };
  for (const flag of ["includesubdomains", "preload"]) {
    if (seen.has(flag) && seen.get(flag) !== undefined) return { valid: false, why: `${flag} takes no value` };
  }
  return { valid: true, maxAge: Number(m[1] ?? m[2]), includeSubDomains: seen.has("includesubdomains"), preload: seen.has("preload") };
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
  if (!h.valid) {
    return { status: "fail", summary: `The HSTS header is malformed (${h.why}), so browsers ignore it.`, fix, facts };
  }
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

type HeaderVerdict = "ok" | "missing" | { weak: string };

/** CSP directives as name → source list (lowercased). The first occurrence of a directive wins, as in browsers. */
function cspDirectives(csp: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const part of csp.split(";")) {
    const [name, ...sources] = part.trim().toLowerCase().split(/\s+/);
    if (name && !out.has(name)) out.set(name, sources);
  }
  return out;
}

const REFERRER_POLICIES = new Set([
  "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
  "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url",
]);
/** Policies that still send full URLs to other sites. */
const LEAKY_REFERRER = new Set(["unsafe-url", "no-referrer-when-downgrade"]);

/** `label` is the short form shown in the facts list; `name` is used in the fix text. Each judges the value, not just presence. */
const HEADER_CHECKS: { label: string; name: string; judge: (h: Headers) => HeaderVerdict }[] = [
  {
    label: "CSP",
    name: "Content-Security-Policy (restricting scripts)",
    judge: (h) => {
      const csp = h.get("content-security-policy");
      if (!csp) return "missing";
      const d = cspDirectives(csp);
      const scripts = d.get("script-src") ?? d.get("default-src");
      if (!scripts) return { weak: "doesn't restrict scripts (no script-src or default-src)" };
      if (scripts.includes("*")) return { weak: "allows scripts from anywhere (*)" };
      return "ok";
    },
  },
  {
    label: "nosniff",
    name: "X-Content-Type-Options: nosniff",
    judge: (h) => {
      const v = h.get("x-content-type-options");
      if (v === null) return "missing";
      return v.trim().toLowerCase() === "nosniff" ? "ok" : { weak: `"${v}" isn't nosniff` };
    },
  },
  {
    label: "Framing",
    name: "clickjacking protection (X-Frame-Options: DENY or SAMEORIGIN, or CSP frame-ancestors)",
    judge: (h) => {
      const ancestors = cspDirectives(h.get("content-security-policy") ?? "").get("frame-ancestors");
      if (ancestors && ancestors.length > 0 && !ancestors.includes("*")) return "ok";
      const xfo = h.get("x-frame-options");
      if (xfo !== null && /^(deny|sameorigin)$/i.test(xfo.trim())) return "ok";
      if (ancestors?.includes("*")) return { weak: "frame-ancestors * allows any site" };
      return xfo === null ? "missing" : { weak: `X-Frame-Options "${xfo}" isn't DENY or SAMEORIGIN` };
    },
  },
  {
    label: "Referrer-Policy",
    name: "Referrer-Policy (e.g. strict-origin-when-cross-origin)",
    judge: (h) => {
      const v = h.get("referrer-policy");
      if (v === null) return "missing";
      // Browsers use the last policy they recognise in a comma-separated list.
      const effective = v.split(",").map((t) => t.trim().toLowerCase()).filter((t) => REFERRER_POLICIES.has(t)).at(-1);
      if (!effective) return { weak: `"${v}" isn't a valid policy` };
      return LEAKY_REFERRER.has(effective) ? { weak: `${effective} sends full URLs to other sites` } : "ok";
    },
  },
  {
    label: "Permissions-Policy",
    name: "Permissions-Policy",
    judge: (h) => {
      const v = h.get("permissions-policy");
      if (v === null) return "missing";
      return /^\s*[a-z-]+=/i.test(v) ? "ok" : { weak: `"${v}" isn't a valid policy` };
    },
  },
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
  const verdicts = HEADER_CHECKS.map((c) => ({ c, v: c.judge(final.headers) }));
  const bad = verdicts.filter(({ v }) => v !== "ok");
  const have = verdicts.length - bad.length;
  const facts = verdicts.map(({ c, v }) => fact(c.label, v === "ok" ? "set" : v === "missing" ? "missing" : `ineffective: ${v.weak}`));
  if (bad.length === 0) return { status: "pass", summary: "All five recommended security headers are set to protective values.", facts };
  const fix = `Set ${bad.map(({ c }) => c.name).join(", ")} at your web server or CDN.`;
  if (have >= 3) return { status: "warn", summary: `${have} of 5 recommended security headers are set to protective values.`, fix, facts };
  return { status: "fail", summary: `Only ${have} of 5 recommended security headers are set to protective values.`, fix, facts };
}
