import { gradeChecks, sha256Hex, type CheckId, type DomainCheck, type DomainReport } from "@bluebench/shared";
import { Budget, BudgetExceeded, Resolver } from "../dns.ts";
import type { Env } from "../env.ts";
import type { Tier } from "../quota.ts";
import { redact, restore } from "../redact.ts";
import { certCheck } from "./cert.ts";
import { dkimCheck, dmarcCheck, dnssecCheck, getMx, mxCheck, spfCheck } from "./email.ts";
import { headersCheck, hstsCheck, httpsCheck, probeWeb } from "./web.ts";

/**
 * Subrequests one report may make. The free plan allows 50 per incoming request; the route itself
 * uses one (the daily-cap Durable Object), so leave headroom.
 */
export const REPORT_BUDGET = 45;
/** Reports are cached briefly: long enough to absorb repeat checks, short enough that fixes show up. */
const REPORT_TTL_S = 3600;

export interface ReportDeps {
  env: Env;
  tier: Tier;
  waitUntil(p: Promise<unknown>): void;
  now?: () => number;
  /**
   * The zone Bluebench itself is served from (e.g. bluebench.dev). Cloudflare doesn't let a Worker fetch
   * sites in its own zone (it answers with an error page), so for those the web checks aren't run.
   */
  selfZone?: string;
}

const inZone = (domain: string, zone?: string) => Boolean(zone) && (domain === zone || domain.endsWith(`.${zone}`));

type Check = Omit<DomainCheck, "id">;

/** Run one check, turning budget exhaustion or an upstream failure into "skipped" rather than an error. */
async function guarded(run: () => Promise<Check> | Check): Promise<Check> {
  try {
    return await run();
  } catch (e) {
    const why = e instanceof BudgetExceeded ? "request budget used up" : "a DNS or network error";
    return { status: "skipped", summary: `Couldn't check this time (${why}).`, facts: [] };
  }
}

export async function runReport(domain: string, deps: ReportDeps): Promise<DomainReport> {
  const now = deps.now?.() ?? Date.now();
  const budget = new Budget(REPORT_BUDGET);
  const r = new Resolver(budget);

  const mxP = getMx(r, domain);
  const receivesMail = mxP.then((mx) => mx.hosts.length > 0).catch(() => true);
  const self = inZone(domain, deps.selfZone);
  const webP = self ? null : probeWeb(r, budget, domain);
  const notFromInside: Check = {
    status: "skipped",
    summary: `Not checked: Bluebench runs inside ${deps.selfZone}'s own Cloudflare zone, and Cloudflare won't let it fetch its own site. Check from outside, e.g. curl -I https://${domain}/`,
    facts: [],
  };
  const web = (judge: (w: Awaited<ReturnType<typeof probeWeb>>) => Check) => () =>
    webP ? webP.then(judge) : Promise.resolve(notFromInside);

  const entries = await Promise.all(
    (
      [
        ["mx", () => mxP.then(mxCheck)],
        ["spf", async () => spfCheck(r, domain, await receivesMail)],
        ["dmarc", async () => dmarcCheck(r, domain, await receivesMail)],
        ["dkim", async () => dkimCheck(r, domain, await receivesMail)],
        ["dnssec", () => mxP.then((mx) => dnssecCheck(mx.answer))],
        ["https", web((w) => httpsCheck(w, domain))],
        ["hsts", web(hstsCheck)],
        ["headers", web(headersCheck)],
        ["cert", () => certCheck(domain, { ...deps, budget, now })],
      ] as [CheckId, () => Promise<Check>][]
    ).map(async ([id, run]) => ({ id, ...(await guarded(run)) })),
  );

  return { ok: true, domain, ...gradeChecks(entries), checks: entries, checkedAt: new Date(now).toISOString() };
}

const inflight = new Map<string, Promise<DomainReport>>();

/** Cached for an hour under a hashed key; concurrent requests for the same domain share one run. */
export async function domainReport(domain: string, deps: ReportDeps): Promise<DomainReport> {
  const key = `report:v2:${await sha256Hex(domain)}`;
  const cached = await deps.env.VERDICTS.get<DomainReport>(key, "json").catch(() => null);
  if (cached) return { ...restore(cached, domain), domain, cached: true };

  let p = inflight.get(domain);
  if (!p) {
    p = runReport(domain, deps)
      .then((report) => {
        // The domain is swapped for a placeholder (and re-attached on read), so KV never holds it.
        deps.waitUntil(
          deps.env.VERDICTS.put(key, JSON.stringify(redact(report, domain)), { expirationTtl: REPORT_TTL_S }).catch(() => {}),
        );
        return report;
      })
      .finally(() => inflight.delete(domain));
    inflight.set(domain, p);
  }
  return p;
}

/** True when a cached report exists, so the per-target limit needn't be spent. */
export async function hasCachedReport(env: Env, domain: string): Promise<boolean> {
  return (await env.VERDICTS.get(`report:v2:${await sha256Hex(domain)}`).catch(() => null)) !== null;
}
