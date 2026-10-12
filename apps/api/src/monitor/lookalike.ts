import { lookalikes } from "@bluebench/shared";
import { eq } from "drizzle-orm";
import type { BatchItem } from "drizzle-orm/batch";
import type { Db } from "../auth.ts";
import { domain, lookalike } from "../db/schema.ts";
import { Budget, BudgetExceeded, DNS_TYPES, Resolver } from "../dns.ts";
import type { AlertText } from "./rules.ts";

/** Subrequests per lookalike run: one A query per variant, plus an MX query for names that exist. */
export const LOOKALIKE_BUDGET = 40;

export type Probe = { exists: false } | { exists: true; web: boolean; mail: boolean };

/**
 * Does a lookalike exist, and does it have a website or mail? NXDOMAIN on the A query means nobody
 * registered it, so most variants cost a single query. Throws on SERVFAIL or a network error: an
 * unknown answer is never treated as "gone".
 */
export async function probe(r: Resolver, name: string): Promise<Probe> {
  const a = await r.query(name, "A");
  if (a.status === 3) return { exists: false };
  if (a.status !== 0) throw new Error(`DNS status ${a.status}`);
  const mx = await r.query(name, "MX");
  if (mx.status !== 0 && mx.status !== 3) throw new Error(`DNS status ${mx.status}`);
  return {
    exists: true,
    web: a.records.some((x) => x.type === DNS_TYPES.A),
    mail: mx.records.some((x) => x.type === DNS_TYPES.MX && !/^0 \.?$/.test(x.data.trim())), // "0 ." is null MX: no mail
  };
}

const defang = (name: string) => name.replace(/\./g, "[.]");
const uses = (h: { web: boolean; mail: boolean }) => [h.web && "website", h.mail && "mail"].filter(Boolean).join(" and ");

export function lookalikeAlert(domainName: string, hits: readonly { name: string; web: boolean; mail: boolean }[]): AlertText {
  const n = hits.length;
  return {
    title: `${domainName}: ${n} new lookalike domain${n === 1 ? "" : "s"}`,
    body: [
      `${n === 1 ? "A domain that looks like" : "Domains that look like"} ${domainName} started resolving:`,
      ...hits.map((h) => `${defang(h.name)} (${uses(h)})`),
      "If you don't own them, watch for phishing that uses them. Your registrar or the host can take down abusive ones.",
    ].join("\n"),
  };
}

type DomainRow = typeof domain.$inferSelect;

export interface ScanResult {
  /** Newly resolving lookalikes (only reported once a baseline scan has finished). */
  fresh: { name: string; web: boolean; mail: boolean }[];
  /** True when this run reached the end of the list. */
  finished: boolean;
}

/**
 * Scan the next chunk of a domain's lookalikes, resuming at its cursor, within the run's budget.
 * Stores hits, deletes ones that stopped resolving, and returns the new ones. `exclude` holds the
 * owner's other saved domains (not lookalikes worth warning about).
 */
export async function scanLookalikes(d: Db, row: DomainRow, now: number, exclude: ReadonlySet<string>, budget = LOOKALIKE_BUDGET): Promise<ScanResult> {
  // Claim it first, so a failure below can't hog every following run.
  await d.update(domain).set({ lookalikeCheckedAt: new Date(now) }).where(eq(domain.id, row.id));

  const variants = lookalikes(row.name).filter((l) => !exclude.has(l.domain));
  const known = new Map((await d.select().from(lookalike).where(eq(lookalike.domainId, row.id))).map((l) => [l.name, l]));
  const r = new Resolver(new Budget(budget));
  const baseline = row.lookalikeScannedAt !== null;
  const fresh: ScanResult["fresh"] = [];
  const writes: BatchItem<"sqlite">[] = [];

  let i = Math.min(row.lookalikeCursor, variants.length);
  for (; i < variants.length; i++) {
    const name = variants[i]!.domain;
    let p: Probe;
    try {
      p = await probe(r, name);
    } catch (e) {
      if (e instanceof BudgetExceeded) break; // resume here next time
      continue; // unknown: leave what we knew
    }
    const prev = known.get(name);
    if (p.exists && (p.web || p.mail)) {
      if (prev) {
        writes.push(d.update(lookalike).set({ web: p.web, mail: p.mail, lastSeenAt: new Date(now) }).where(eq(lookalike.id, prev.id)));
      } else {
        writes.push(
          d.insert(lookalike).values({ id: crypto.randomUUID(), domainId: row.id, name, web: p.web, mail: p.mail, firstSeenAt: new Date(now), lastSeenAt: new Date(now) }),
        );
        if (baseline) fresh.push({ name, web: p.web, mail: p.mail });
      }
    } else if (prev) {
      writes.push(d.delete(lookalike).where(eq(lookalike.id, prev.id)));
    }
  }

  const finished = i >= variants.length;
  const progress = d
    .update(domain)
    .set(finished ? { lookalikeCursor: 0, lookalikeScannedAt: new Date(now) } : { lookalikeCursor: i })
    .where(eq(domain.id, row.id));
  await d.batch([progress, ...writes]);
  return { fresh, finished };
}
