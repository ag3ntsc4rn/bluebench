import { KEV_KV_KEYS, type KevResponse, type ServiceCheck, type SourceId, type StatusResponse } from "@bluebench/shared";
import { eq } from "drizzle-orm";
import type { BatchItem } from "drizzle-orm/batch";
import type { Db } from "../auth.ts";
import { alert, healthCheck, user } from "../db/schema.ts";
import { Budget } from "../dns.ts";
import { probeCertificates } from "../domain/cert.ts";
import type { Env } from "../env.ts";
import { PROVIDERS } from "../providers.ts";

/**
 * The watchdog: once an hour, check each outside service Bluebench depends on with a query whose
 * answer we know, store the results (GET /api/status shows them), and tell the owner when a check
 * fails twice in a row, and again when it recovers. No user data is involved.
 */

type Outcome = { ok: boolean; detail: string } | "off";

interface Check {
  id: string;
  label: string;
  /**
   * Which cron run of the hour checks this (minute 45 + part). Running every check in one go took
   * ~23 ms of CPU, over the free plan's 10 ms per run; a run that is over every time gets terminated.
   */
  part: number;
  run(env: Env, now: number): Promise<Outcome>;
}

/** WannaCry ransomware sample: one of the most documented, so MalwareBazaar must list it. */
export const KNOWN_BAD_SHA256 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa";
/** The Intel data is rebuilt at least daily (14:15 UTC); older than this means the job is failing. */
const INTEL_MAX_AGE_MS = 36 * 3600_000;
/** Failed runs in a row before the owner is told (one blip isn't worth a notification). */
export const FAILURES_BEFORE_ALERT = 2;

/** The source answers at all (a "not listed" answer is a healthy answer). */
function answers(source: SourceId, kind: "domain" | "sha256", value: string, mustList = false): Check["run"] {
  return async (env) => {
    if (!PROVIDERS[source].configured(env)) return "off";
    try {
      const a = await PROVIDERS[source].query(env, kind, value);
      if (mustList && a.status !== "listed") return { ok: false, detail: `expected the WannaCry sample to be listed, got "${a.status}"` };
      return { ok: true, detail: a.status };
    } catch (e) {
      return { ok: false, detail: (e as Error).message || "error" };
    }
  };
}

export const CHECKS: readonly Check[] = [
  { id: "urlhaus", label: "URLhaus", part: 0, run: answers("urlhaus", "domain", "example.com") },
  { id: "threatfox", label: "ThreatFox", part: 0, run: answers("threatfox", "domain", "example.com") },
  { id: "malwarebazaar", label: "MalwareBazaar", part: 1, run: answers("malwarebazaar", "sha256", KNOWN_BAD_SHA256, true) },
  { id: "safebrowsing", label: "Google Safe Browsing", part: 0, run: answers("safebrowsing", "domain", "example.com") },
  {
    id: "intel",
    label: "Exploited vulnerabilities data",
    part: 1, // parses the ~70 KB recent KEV document
    async run(env, now) {
      const raw = await env.VERDICTS.get(KEV_KV_KEYS.recent).catch(() => null);
      if (!raw) return { ok: false, detail: "no data stored" };
      try {
        const age = now - Date.parse((JSON.parse(raw) as KevResponse).updatedAt);
        const hours = Math.round(age / 3600_000);
        return Number.isFinite(age) && age <= INTEL_MAX_AGE_MS ? { ok: true, detail: `updated ${hours} h ago` } : { ok: false, detail: `last updated ${hours} h ago` };
      } catch {
        return { ok: false, detail: "stored data unreadable" };
      }
    },
  },
  {
    id: "certificates",
    label: "Certificate Transparency search",
    part: 2, // crt.sh, and up to three Cert Spotter pages when it fails
    async run(env, now) {
      const r = await probeCertificates(new URL(env.SITE_ORIGIN).hostname, { env, budget: new Budget(6), tier: "user", waitUntil: () => {}, now });
      return r.ok ? { ok: true, detail: `${r.source} answered` } : { ok: false, detail: r.why };
    },
  },
];

type Row = typeof healthCheck.$inferSelect;

const hhmm = (d: Date) => `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;

export const WATCHDOG_PARTS = Math.max(...CHECKS.map((c) => c.part)) + 1;

/**
 * Run the checks of one part (all of them when `part` is omitted) and store the results. The last part
 * also tells the owner about new failure streaks and recoveries across every check, in one alert.
 * Until that summary, a check that recovered keeps `alerted` (and its `failingSince`) so it's announced.
 */
export async function runWatchdog(env: Env, d: Db, now: number, part?: number): Promise<Row[]> {
  const prev = new Map((await d.select().from(healthCheck)).map((r) => [r.id, r]));
  const checks = CHECKS.filter((c) => part === undefined || c.part === part);
  const outcomes = await Promise.all(checks.map(async (c) => [c, await c.run(env, now).catch((e: Error) => ({ ok: false, detail: e.message }))] as const));

  const at = new Date(now);
  const fresh = new Map<string, Row>();
  for (const [check, out] of outcomes) {
    const before = prev.get(check.id);
    if (out === "off") {
      fresh.set(check.id, { id: check.id, ok: true, detail: "off", checkedAt: at, failingSince: null, failures: 0, alerted: false });
    } else if (out.ok) {
      const recovering = Boolean(before?.alerted);
      fresh.set(check.id, { id: check.id, ok: true, detail: out.detail, checkedAt: at, failingSince: recovering ? (before!.failingSince ?? at) : null, failures: 0, alerted: recovering });
    } else {
      const failures = (before?.ok === false ? before.failures : 0) + 1;
      const failingSince = before?.ok === false ? (before.failingSince ?? at) : at;
      fresh.set(check.id, { id: check.id, ok: false, detail: out.detail, checkedAt: at, failingSince, failures, alerted: Boolean(before?.alerted) });
    }
  }

  const news: string[] = [];
  const fixed: string[] = [];
  if (part === undefined || part === WATCHDOG_PARTS - 1) {
    for (const check of CHECKS) {
      const row = fresh.get(check.id) ?? prev.get(check.id);
      if (!row) continue;
      if (!row.ok && row.failures >= FAILURES_BEFORE_ALERT && !row.alerted) {
        news.push(`${check.label} has been failing since ${hhmm(row.failingSince ?? at)}: ${row.detail}.`);
        fresh.set(check.id, { ...row, alerted: true });
      } else if (row.ok && row.alerted) {
        fixed.push(`${check.label} is working again (it had been failing since ${hhmm(row.failingSince ?? at)}).`);
        fresh.set(check.id, { ...row, alerted: false, failingSince: null });
      }
    }
  }
  const rows = [...fresh.values()];

  const writes: BatchItem<"sqlite">[] = [];
  const owner = env.OWNER_EMAIL && (news.length > 0 || fixed.length > 0)
    ? (await d.select({ id: user.id }).from(user).where(eq(user.email, env.OWNER_EMAIL.trim().toLowerCase())))[0]
    : undefined;
  if (owner) {
    const title = news.length > 0 ? `Bluebench: ${news.length === 1 ? "a check is failing" : `${news.length} checks are failing`}` : "Bluebench: all clear again";
    writes.push(
      d.insert(alert).values({
        id: crypto.randomUUID(),
        userId: owner.id,
        domainId: null,
        domain: null,
        kind: "health",
        title,
        body: [...news, ...fixed, "", `Status: ${env.SITE_ORIGIN}/about`].join("\n"),
        createdAt: at,
      }),
    );
  }
  const upserts = rows.map((r) => d.insert(healthCheck).values(r).onConflictDoUpdate({ target: healthCheck.id, set: { ...r } }));
  await d.batch([upserts[0]!, ...upserts.slice(1), ...writes]);
  return rows;
}

/** For GET /api/status: the stored results, in CHECKS order. */
export async function serviceStatus(d: Db): Promise<StatusResponse> {
  const rows = new Map((await d.select().from(healthCheck)).map((r) => [r.id, r]));
  const checks: ServiceCheck[] = CHECKS.map((c) => {
    const r = rows.get(c.id);
    const state = !r || r.detail === "off" ? "off" : r.ok ? "ok" : "failing";
    return { id: c.id, label: c.label, state, since: state === "failing" ? (r?.failingSince?.toISOString() ?? null) : null };
  });
  const times = [...rows.values()].map((r) => r.checkedAt.getTime());
  return { ok: true, checkedAt: times.length > 0 ? new Date(Math.max(...times)).toISOString() : null, checks };
}
