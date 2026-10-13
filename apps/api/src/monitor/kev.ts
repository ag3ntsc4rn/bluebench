import { KEV_KV_KEYS, watchKey, watchMatches, type KevEntry, type KevResponse } from "@bluebench/shared";
import { eq, inArray, lt } from "drizzle-orm";
import type { BatchItem } from "drizzle-orm/batch";
import type { Db } from "../auth.ts";
import { alert, intelState, kevSeen, watch } from "../db/schema.ts";
import type { Env } from "../env.ts";
import type { AlertText } from "./rules.ts";

const STATE_KEY = "kev_updated_at";
/** Seen entries are kept past the 90-day recent window, so an entry can't alert twice. */
export const KEV_SEEN_RETENTION_MS = 120 * 86_400_000;
/** D1 allows 100 bound parameters per query: 90 values in an IN list, or 40 two-column rows per insert. */
const chunks = <T>(xs: readonly T[], size = 90) => Array.from({ length: Math.ceil(xs.length / size) }, (_, i) => xs.slice(i * size, (i + 1) * size));

export function kevAlert(entries: readonly KevEntry[], siteOrigin: string): AlertText {
  const first = entries[0]!;
  const title =
    entries.length === 1
      ? `${first.vendor} ${first.product}: actively exploited (${first.cve})`
      : `${entries.length} newly exploited vulnerabilities in products you watch`;
  const lines = entries.map((e) => `${e.cve}: ${e.vendor} ${e.product}. ${e.name}.${e.ransomware ? " Used in ransomware." : ""} ${e.action}`);
  return { title, body: [...lines, "", `Details: ${siteOrigin}/exploited-vulnerabilities`].join("\n") };
}

export type KevCheck = "no-data" | "unchanged" | "baseline" | "checked";

/**
 * Once an hour: if the stored KEV list changed since last time, alert each account whose watchlist
 * matches an entry not seen before (one alert per account per run). The first run only records
 * what's already listed, so turning this on doesn't flood anyone.
 */
export async function checkKev(env: Env, d: Db, now: number): Promise<KevCheck> {
  const raw = await env.VERDICTS.get(KEV_KV_KEYS.recent).catch(() => null);
  if (!raw) return "no-data";
  let doc: KevResponse;
  try {
    doc = JSON.parse(raw) as KevResponse;
  } catch {
    return "no-data";
  }
  if (!Array.isArray(doc.entries) || typeof doc.updatedAt !== "string") return "no-data";

  const [state] = await d.select().from(intelState).where(eq(intelState.key, STATE_KEY));
  if (state?.value === doc.updatedAt) return "unchanged";

  const cves = doc.entries.map((e) => e.cve);
  const seen = new Set<string>();
  for (const part of chunks(cves)) {
    for (const r of await d.select({ cve: kevSeen.cve }).from(kevSeen).where(inArray(kevSeen.cve, part))) seen.add(r.cve);
  }
  const fresh = doc.entries.filter((e) => !seen.has(e.cve));
  const baseline = !state;

  const writes: BatchItem<"sqlite">[] = [];
  if (!baseline && fresh.length > 0) {
    const vendorKeys = [...new Set(fresh.map((e) => watchKey(e.vendor)))];
    const watches = [];
    for (const part of chunks(vendorKeys)) watches.push(...(await d.select().from(watch).where(inArray(watch.vendorKey, part))));

    const byUser = new Map<string, KevEntry[]>();
    for (const e of fresh) {
      for (const w of watches) {
        if (!watchMatches(w, e)) continue;
        const list = byUser.get(w.userId) ?? [];
        if (!list.includes(e)) list.push(e);
        byUser.set(w.userId, list);
      }
    }
    for (const [userId, entries] of byUser) {
      const text = kevAlert(entries, env.SITE_ORIGIN);
      writes.push(
        d.insert(alert).values({ id: crypto.randomUUID(), userId, domainId: null, domain: null, kind: "kev", title: text.title, body: text.body, createdAt: new Date(now) }),
      );
    }
  }
  for (const part of chunks(fresh, 40)) {
    writes.push(d.insert(kevSeen).values(part.map((e) => ({ cve: e.cve, seenAt: new Date(now) }))).onConflictDoNothing());
  }
  const progress = d
    .insert(intelState)
    .values({ key: STATE_KEY, value: doc.updatedAt })
    .onConflictDoUpdate({ target: intelState.key, set: { value: doc.updatedAt } });
  await d.batch([progress, ...writes]);
  return baseline ? "baseline" : "checked";
}

/** Housekeeping: forget entries seen long ago (they've left the 90-day list for good). */
export const pruneKevSeen = (d: Db, now: number) => d.delete(kevSeen).where(lt(kevSeen.seenAt, new Date(now - KEV_SEEN_RETENTION_MS)));
