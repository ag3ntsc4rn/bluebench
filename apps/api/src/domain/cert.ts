import { sha256Hex, type DomainCheck } from "@bluebench/shared";
import type { Budget } from "../dns.ts";
import type { Env } from "../env.ts";
import type { Tier } from "../quota.ts";

type Check = Omit<DomainCheck, "id">;
const fact = (label: string, value: string) => ({ label, value });

const CRTSH_TIMEOUT_MS = 8000;
/** Busy domains have thousands of certificates; parsing megabytes would blow the 10 ms CPU limit. */
const MAX_BODY_BYTES = 1_000_000;
/** crt.sh asks for restraint; certificates change rarely. Daily re-check at most. */
const CACHE_TTL_S = 24 * 3600;
const DAY_MS = 86_400_000;

/** One row of crt.sh's JSON output (the fields we use). */
export interface CtEntry {
  issuer_name?: string;
  name_value?: string;
  not_before?: string;
  not_after?: string;
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

/** A check plus the certificate it judged, which monitoring uses for expiry alerts. */
export type CertCheck = Check & { current?: CertEntry };

/** Judge the newest unexpired certificate. Pure, so it can be tested without crt.sh. */
export function judgeCerts(entries: CertEntry[], now: number): CertCheck {
  const current = entries.filter((e) => utc(e.notAfter) > now).sort((a, b) => utc(b.notBefore) - utc(a.notBefore));
  if (current.length === 0) {
    // crt.sh often lags or returns partial results, so absence isn't graded; the HTTPS check covers a missing certificate.
    return { status: "skipped", summary: "crt.sh has no current certificate on record for this name (its data can lag).", facts: [] };
  }
  const newest = current[0]!;
  const days = Math.floor((utc(newest.notAfter) - now) / DAY_MS);
  const facts = [fact("Issuer", newest.issuer), fact("Issued", newest.notBefore.slice(0, 10)), fact("Expires", newest.notAfter.slice(0, 10))];
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
}

/** Certificate expiry and issuer from crt.sh, cached for a day and rate-limited through its quota object. */
export async function certCheck(domain: string, deps: CertDeps): Promise<CertCheck> {
  const { env, budget, now } = deps;
  const key = `cert:v1:${await sha256Hex(domain)}`;
  const cached = await env.VERDICTS.get<{ entries: CertEntry[] }>(key, "json").catch(() => null);
  if (cached) return judgeCerts(cached.entries, now);

  const skipped = (why: string): Check => ({ status: "skipped", summary: `Couldn't check certificates this time: ${why}.`, facts: [] });
  if (!budget.take()) return skipped("request budget used up");
  const quota = env.PROVIDER_QUOTA.get(env.PROVIDER_QUOTA.idFromName("crtsh"));
  const permit = await quota.acquire("crtsh", deps.tier).catch(() => ({ ok: false as const, reason: "rate" as const }));
  if (!permit.ok) return skipped(permit.reason === "daily" ? "today's crt.sh budget is used up" : "crt.sh is busy, try again in a minute");

  // crt.sh is often overloaded (502s). If the broad query fails, try once more with the lighter exact-match query.
  const base = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json&exclude=expired&deduplicate=Y`;
  let entries: CertEntry[] | null = null;
  for (const url of [base, `${base}&match=%3D`]) {
    if (!budget.take()) return skipped("request budget used up");
    try {
      const res = await fetch(url, {
        headers: { accept: "application/json", "user-agent": "Bluebench/1.0 (+https://bluebench.dev)" },
        signal: AbortSignal.timeout(CRTSH_TIMEOUT_MS),
      });
      if (res.status >= 502 && res.status <= 504) continue;
      if (!res.ok) return skipped("crt.sh didn't answer");
      const parsed: unknown = JSON.parse((await readCapped(res, MAX_BODY_BYTES)) || "[]");
      if (!Array.isArray(parsed)) return skipped("crt.sh sent an unexpected answer");
      entries = toCertEntries(parsed as CtEntry[], domain);
      break;
    } catch (e) {
      if (e instanceof TooLarge) return skipped("this domain has too many certificates to check quickly");
      return skipped("crt.sh didn't answer in time");
    }
  }
  if (!entries) return skipped("crt.sh is overloaded right now");
  // Empty answers aren't cached: they're as likely a crt.sh hiccup as the truth.
  if (entries.length === 0) return judgeCerts(entries, now);
  deps.waitUntil(env.VERDICTS.put(key, JSON.stringify({ entries }), { expirationTtl: CACHE_TTL_S }).catch(() => {}));
  return judgeCerts(entries, now);
}
