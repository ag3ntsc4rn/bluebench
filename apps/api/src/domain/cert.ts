import { sha256Hex, type DomainCheck } from "@bluebench/shared";
import { cachePut } from "../cache.ts";
import type { Budget } from "../dns.ts";
import type { Env } from "../env.ts";
import type { Tier } from "../quota.ts";

type Check = Omit<DomainCheck, "id">;
const fact = (label: string, value: string) => ({ label, value });

const CT_TIMEOUT_MS = 8000;
/** Busy domains have thousands of certificates; parsing megabytes would blow the 10 ms CPU limit. */
const MAX_BODY_BYTES = 1_000_000;
/** crt.sh and Cert Spotter ask for restraint; certificates change rarely. Daily re-check at most. */
const CACHE_TTL_S = 24 * 3600;
const DAY_MS = 86_400_000;

/** One row of crt.sh's JSON output (the fields we use). */
export interface CtEntry {
  issuer_name?: string;
  name_value?: string;
  not_before?: string;
  not_after?: string;
}

/** One issuance from Cert Spotter's /v1/issuances (with expand=dns_names&expand=issuer). */
export interface CertSpotterIssuance {
  id?: string;
  dns_names?: string[];
  issuer?: { friendly_name?: string; name?: string };
  not_before?: string;
  not_after?: string;
  revoked?: boolean;
}

/** A certificate known to cover the host: issuer and dates only, so cached data holds no hostnames. */
export interface CertEntry {
  issuer: string;
  notBefore: string;
  notAfter: string;
}

class TooLarge extends Error {}

async function readCapped(res: Response, max: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      throw new TooLarge();
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(all);
}

/** crt.sh dates are UTC without a zone: "2026-12-01T12:00:00". */
export const utc = (s: string) => Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${s}Z`);

/** Does a certificate's name list cover this exact host (directly or by a one-level wildcard)? */
export function covers(nameValue: string, domain: string): boolean {
  const parent = domain.slice(domain.indexOf(".") + 1);
  return nameValue
    .toLowerCase()
    .split(/\s+/)
    .some((n) => n === domain || n === `*.${parent}`);
}

const issuerOrg = (issuer: string) => /(?:^|,\s*)O=("?)([^,"]+)\1/.exec(issuer)?.[2] ?? /CN=([^,]+)/.exec(issuer)?.[1] ?? "unknown";

/** Keep only certificates that cover this host, reduced to issuer and dates. */
export function toCertEntries(rows: CtEntry[], domain: string): CertEntry[] {
  return rows
    .filter((e) => typeof e.name_value === "string" && e.not_before && e.not_after && covers(e.name_value, domain))
    .map((e) => ({ issuer: issuerOrg(e.issuer_name ?? ""), notBefore: e.not_before!, notAfter: e.not_after! }));
}

/** Keep Cert Spotter issuances that cover this host and aren't revoked, reduced to issuer and dates. */
export function certSpotterEntries(rows: CertSpotterIssuance[], domain: string): CertEntry[] {
  return rows
    .filter((e) => Array.isArray(e.dns_names) && e.not_before && e.not_after && e.revoked !== true && covers(e.dns_names.join(" "), domain))
    .map((e) => ({
      issuer: e.issuer?.friendly_name ?? issuerOrg(e.issuer?.name ?? ""),
      notBefore: e.not_before!,
      notAfter: e.not_after!,
    }));
}

/** Where certificate data came from; shown as a fact on the check. */
export type CtSource = "crt.sh" | "Cert Spotter";

/** A check plus the certificate it judged, which monitoring uses for expiry alerts. */
export type CertCheck = Check & { current?: CertEntry };

/** Judge the newest unexpired certificate. Pure, so it can be tested without a log service. */
export function judgeCerts(entries: CertEntry[], now: number, source: CtSource = "crt.sh"): CertCheck {
  const current = entries.filter((e) => utc(e.notAfter) > now).sort((a, b) => utc(b.notBefore) - utc(a.notBefore));
  if (current.length === 0) {
    // CT search services lag or return partial results, so absence isn't graded; the HTTPS check covers a missing certificate.
    return { status: "skipped", summary: "Certificate Transparency search has no current certificate on record for this name (its data can lag).", facts: [] };
  }
  const newest = current[0]!;
  const days = Math.floor((utc(newest.notAfter) - now) / DAY_MS);
  const facts = [
    fact("Issuer", newest.issuer),
    fact("Issued", newest.notBefore.slice(0, 10)),
    fact("Expires", newest.notAfter.slice(0, 10)),
    fact("Source", source),
  ];
  const when = days <= 0 ? "today" : `in ${days} day${days === 1 ? "" : "s"}`;
  const fix = "Check that automatic renewal is working at your host or certificate provider.";
  // Short-lived certificates (Let's Encrypt is moving to ~45 days) renew with about two weeks left.
  if (days < 7) return { status: "fail", summary: `The newest certificate expires ${when}.`, fix, facts, current: newest };
  if (days < 14) return { status: "warn", summary: `The newest certificate expires ${when}.`, fix, facts, current: newest };
  return { status: "pass", summary: `The newest certificate expires ${when}, issued by ${newest.issuer}.`, facts, current: newest };
}

export interface CertDeps {
  env: Env;
  budget: Budget;
  tier: Tier;
  waitUntil(p: Promise<unknown>): void;
  now: number;
  /** False skips writing the cache (reads still happen); see ReportDeps.cacheWrites. */
  cacheWrites?: boolean;
}

type Fetched = { ok: true; entries: CertEntry[] } | { ok: false; why: string };

const UA = { "user-agent": "Bluebench/1.0 (+https://bluebench.dev)" };

/** Quota permits for `cost` calls to one source, unless the report's request budget is spent. Returns why not, or null. */
async function acquire(deps: CertDeps, key: "crtsh" | "certspotter", cost = 1): Promise<string | null> {
  if (deps.budget.used >= deps.budget.max) return "request budget used up";
  const quota = deps.env.PROVIDER_QUOTA.get(deps.env.PROVIDER_QUOTA.idFromName(key));
  const permit = await quota.acquire(key, deps.tier, undefined, cost).catch(() => ({ ok: false as const, reason: "rate" as const }));
  const name = key === "crtsh" ? "crt.sh" : "Cert Spotter";
  return permit.ok ? null : permit.reason === "daily" ? `today's ${name} budget is used up` : `${name} is busy, try again in a minute`;
}

/**
 * crt.sh: the broad query, then once more with the lighter exact-match query if it's overloaded (502s are
 * common). Each request takes its own quota permit, so retries count against crt.sh's limits too.
 */
async function fromCrtsh(domain: string, deps: CertDeps): Promise<Fetched> {
  const base = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json&exclude=expired&deduplicate=Y`;
  for (const url of [base, `${base}&match=%3D`]) {
    const denied = await acquire(deps, "crtsh");
    if (denied) return { ok: false, why: url === base ? denied : `crt.sh is overloaded, and ${denied}` };
    if (!deps.budget.take()) return { ok: false, why: "request budget used up" };
    try {
      const res = await fetch(url, { headers: { accept: "application/json", ...UA }, signal: AbortSignal.timeout(CT_TIMEOUT_MS) });
      if (res.status >= 502 && res.status <= 504) continue;
      if (!res.ok) return { ok: false, why: "crt.sh didn't answer" };
      const parsed: unknown = JSON.parse((await readCapped(res, MAX_BODY_BYTES)) || "[]");
      if (!Array.isArray(parsed)) return { ok: false, why: "crt.sh sent an unexpected answer" };
      return { ok: true, entries: toCertEntries(parsed as CtEntry[], domain) };
    } catch (e) {
      if (e instanceof TooLarge) return { ok: false, why: "this domain has too many certificates to check quickly" };
      return { ok: false, why: "crt.sh didn't answer in time" };
    }
  }
  return { ok: false, why: "crt.sh is overloaded right now" };
}

/**
 * Cert Spotter returns unexpired issuances in discovery order, 100 a page, ending with an empty page.
 * The newest certificate may be on the last page, so we read to the end; a domain with more than this
 * many pages is skipped rather than judged on a partial list (that could raise a false expiry alert).
 */
export const CERTSPOTTER_MAX_PAGES = 3;

async function fromCertSpotter(domain: string, deps: CertDeps): Promise<Fetched> {
  const key = deps.env.CERTSPOTTER_API_KEY;
  if (!key) return { ok: false, why: "Cert Spotter isn't switched on" };
  // Every page counts against Cert Spotter's hourly limit. The usual answer is two pages (results, then the
  // empty page that ends the list), so reserve those now and one more for each extra page.
  const denied = await acquire(deps, "certspotter", 2);
  if (denied) return { ok: false, why: denied };
  const base = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=false&match_wildcards=true&expand=dns_names&expand=issuer`;
  const entries: CertEntry[] = [];
  let after: string | undefined;
  for (let page = 0; page <= CERTSPOTTER_MAX_PAGES; page++) {
    if (page >= 2) {
      const more = await acquire(deps, "certspotter");
      if (more) return { ok: false, why: more };
    }
    if (!deps.budget.take()) return { ok: false, why: "request budget used up" };
    try {
      const res = await fetch(after ? `${base}&after=${encodeURIComponent(after)}` : base, {
        headers: { accept: "application/json", authorization: `Bearer ${key}`, ...UA },
        signal: AbortSignal.timeout(CT_TIMEOUT_MS),
      });
      if (!res.ok) return { ok: false, why: "Cert Spotter didn't answer" };
      const parsed: unknown = JSON.parse((await readCapped(res, MAX_BODY_BYTES)) || "[]");
      if (!Array.isArray(parsed)) return { ok: false, why: "Cert Spotter sent an unexpected answer" };
      if (parsed.length === 0) return { ok: true, entries };
      if (page === CERTSPOTTER_MAX_PAGES) break;
      const rows = parsed as CertSpotterIssuance[];
      entries.push(...certSpotterEntries(rows, domain));
      after = rows.at(-1)?.id;
      if (!after) return { ok: false, why: "Cert Spotter sent an unexpected answer" };
    } catch (e) {
      if (e instanceof TooLarge) return { ok: false, why: "this domain has too many certificates to check quickly" };
      return { ok: false, why: "Cert Spotter didn't answer in time" };
    }
  }
  return { ok: false, why: "this domain has too many certificates to check quickly" };
}

/**
 * Certificate expiry and issuer from Certificate Transparency: crt.sh first, then SSLMate's Cert Spotter
 * when crt.sh fails or comes back empty (it's often overloaded). Cached for a day, each source
 * rate-limited through its quota object. Empty answers aren't cached: they're as likely a hiccup as the truth.
 */
export async function certCheck(domain: string, deps: CertDeps): Promise<CertCheck> {
  const { env, budget, now } = deps;
  const key = `cert:v2:${await sha256Hex(domain)}`;
  const cached = await env.VERDICTS.get<{ entries: CertEntry[]; source: CtSource }>(key, "json").catch(() => null);
  if (cached) return judgeCerts(cached.entries, now, cached.source);

  if (budget.used >= budget.max) return skipped("request budget used up");
  let source: CtSource = "crt.sh";
  let got = await fromCrtsh(domain, deps);
  if ((!got.ok || got.entries.length === 0) && env.CERTSPOTTER_API_KEY) {
    const fallback = await fromCertSpotter(domain, deps);
    if (fallback.ok) {
      got = fallback;
      source = "Cert Spotter";
    } else if (!got.ok) {
      got = { ok: false, why: `${got.why}, and ${fallback.why.replace(/^this domain/, "the domain")}` };
    }
  }
  if (!got.ok) return skipped(got.why);
  if (got.entries.length > 0 && deps.cacheWrites !== false) {
    cachePut(deps, key, JSON.stringify({ entries: got.entries, source }), CACHE_TTL_S);
  }
  return judgeCerts(got.entries, now, source);
}

const skipped = (why: string): Check => ({ status: "skipped", summary: `Couldn't check certificates this time: ${why}.`, facts: [] });

/** For the watchdog: ask crt.sh, then Cert Spotter, for a domain's certificates, skipping our cache. */
export async function probeCertificates(domain: string, deps: CertDeps): Promise<{ ok: true; source: CtSource; count: number } | { ok: false; why: string }> {
  const crt = await fromCrtsh(domain, deps);
  if (crt.ok && crt.entries.length > 0) return { ok: true, source: "crt.sh", count: crt.entries.length };
  const spotter = await fromCertSpotter(domain, deps);
  if (spotter.ok && spotter.entries.length > 0) return { ok: true, source: "Cert Spotter", count: spotter.entries.length };
  const why = (r: typeof crt) => (r.ok ? "no certificates" : r.why);
  return { ok: false, why: `crt.sh: ${why(crt)}; Cert Spotter: ${why(spotter)}` };
}
