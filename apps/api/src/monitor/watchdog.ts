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
  { id: "urlhaus", label: "URLhaus", run: answers("urlhaus", "domain", "example.com") },
  { id: "threatfox", label: "ThreatFox", run: answers("threatfox", "domain", "example.com") },
  { id: "malwarebazaar", label: "MalwareBazaar", run: answers("malwarebazaar", "sha256", KNOWN_BAD_SHA256, true) },
  { id: "safebrowsing", label: "Google Safe Browsing", run: answers("safebrowsing", "domain", "example.com") },
  {
    id: "intel",
    label: "Exploited vulnerabilities data",
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
    async run(env, now) {
      const r = await probeCertificates(new URL(env.SITE_ORIGIN).hostname, { env, budget: new Budget(6), tier: "user", waitUntil: () => {}, now });
      return r.ok ? { ok: true, detail: `${r.source} answered` } : { ok: false, detail: r.why };
    },
  },
];

type Row = typeof healthCheck.$inferSelect;

const hhmm = (d: Date) => `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;

/** Run every check, store the results, and alert the owner on a new failure streak or a recovery. */
export async function runWatchdog(env: Env, d: Db, now: number): Promise<Row[]> {
  const prev = new Map((await d.select().from(healthCheck)).map((r) => [r.id, r]));
  const outcomes = await Promise.all(CHECKS.map(async (c) => [c, await c.run(env, now).catch((e: Error) => ({ ok: false, detail: e.message }))] as const));

  const at = new Date(now);
  const rows: Row[] = [];
  const news: string[] = [];
  const fixed: string[] = [];
  for (const [check, out] of outcomes) {
    const before = prev.get(check.id);
    if (out === "off") {
      rows.push({ id: check.id, ok: true, detail: "off", checkedAt: at, failingSince: null, failures: 0, alerted: false });
      continue;
    }
    if (out.ok) {
      if (before?.alerted) fixed.push(`${check.label} is working again (it had been failing since ${hhmm(before.failingSince ?? at)}).`);
      rows.push({ id: check.id, ok: true, detail: out.detail, checkedAt: at, failingSince: null, failures: 0, alerted: false });
      continue;
    }
    const failures = (before?.ok === false ? before.failures : 0) + 1;
    const failingSince = before?.ok === false ? (before.failingSince ?? at) : at;
    const alertNow = failures >= FAILURES_BEFORE_ALERT && !before?.alerted;
    if (alertNow) news.push(`${check.label} has been failing since ${hhmm(failingSince)}: ${out.detail}.`);
    rows.push({ id: check.id, ok: false, detail: out.detail, checkedAt: at, failingSince, failures, alerted: Boolean(before?.alerted) || alertNow });
  }

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
    return { id: c.id, label: c.label, state, since: r?.failingSince?.toISOString() ?? null };
  });
  const times = [...rows.values()].map((r) => r.checkedAt.getTime());
  return { ok: true, checkedAt: times.length > 0 ? new Date(Math.max(...times)).toISOString() : null, checks };
}
