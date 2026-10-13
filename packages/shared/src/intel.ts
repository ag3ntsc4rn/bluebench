import { z } from "zod";

/**
 * Known exploited vulnerabilities (CISA KEV, CC0) with exploit-likelihood scores (FIRST EPSS, free;
 * attribution requested). A scheduled GitHub Actions job builds this document and stores it in KV
 * (scripts/update-intel.ts); GET /api/intel/kev serves it as-is (no parsing in the Worker) and the
 * Intel tab renders it.
 */

export const KEV_SOURCE_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
export const EPSS_SOURCE_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
/**
 * KV keys: the last RECENT_DAYS of entries (loaded with the page, ~14 KB compressed) and the whole
 * catalogue (~175 KB, loaded only to search or show older entries). Bump the version when the shape changes.
 */
export const KEV_KV_KEYS = { recent: "intel:kev:recent:v1", all: "intel:kev:all:v1" } as const;
export type KevScope = keyof typeof KEV_KV_KEYS;
export const RECENT_DAYS = 90;

/** KEV has ~1,700 entries and grows; far fewer means a broken download, which must not replace good data. */
export const KEV_MIN_ENTRIES = 1000;

export const KevEntrySchema = z.object({
  cve: z.string().regex(/^CVE-\d{4}-\d{4,}$/),
  vendor: z.string(),
  product: z.string(),
  name: z.string(),
  /** YYYY-MM-DD */
  added: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  description: z.string(),
  action: z.string(),
  /** CISA's remediation deadline for US federal agencies, YYYY-MM-DD. */
  due: z.string(),
  ransomware: z.boolean(),
  /** First vendor advisory or reference link from KEV's notes, if any. */
  advisory: z.string().url().optional(),
  /** EPSS probability (0–1) and percentile (0–1), when FIRST has scored the CVE. */
  epss: z.number().min(0).max(1).optional(),
  percentile: z.number().min(0).max(1).optional(),
});
export type KevEntry = z.infer<typeof KevEntrySchema>;

export const KevDocumentSchema = z.object({
  /** When the job built this document (ISO). */
  updatedAt: z.string(),
  /** KEV's own catalogVersion, e.g. "2026.10.08". */
  catalogVersion: z.string(),
  /** Date of the EPSS scores used, or null if EPSS was unavailable. */
  epssDate: z.string().nullable(),
  /** Newest first. */
  entries: z.array(KevEntrySchema),
});
export type KevDocument = z.infer<typeof KevDocumentSchema>;

/** What GET /api/intel/kev returns, and exactly what's stored in KV. */
export interface KevResponse extends KevDocument {
  ok: true;
}

/** One row of CISA's KEV JSON (the fields we use). */
interface RawKev {
  cveID?: unknown;
  vendorProject?: unknown;
  product?: unknown;
  vulnerabilityName?: unknown;
  dateAdded?: unknown;
  shortDescription?: unknown;
  requiredAction?: unknown;
  dueDate?: unknown;
  knownRansomwareCampaignUse?: unknown;
  notes?: unknown;
}

const text = (v: unknown) => (typeof v === "string" ? v.trim() : "");

/** First https link in KEV's notes field (they're separated by " ; "). */
export function firstAdvisory(notes: unknown): string | undefined {
  const m = /https:\/\/[^\s;]+/.exec(text(notes));
  if (!m) return undefined;
  try {
    return new URL(m[0]).href;
  } catch {
    return undefined;
  }
}

/**
 * CISA's "required action" is mostly US-federal boilerplate ("…per vendor instructions, follow applicable
 * BOD 22-01 guidance…"). Turn the boilerplate into a plain instruction for everyone else; keep anything
 * specific as CISA wrote it.
 */
export function plainAction(action: string): string {
  const a = action.toLowerCase();
  if (a.includes("end-of-life") && (a.includes("disconnect") || a.includes("impacted product is"))) {
    return "The product is end-of-life and won't be fixed: replace it, or take it offline until you can.";
  }
  if (!/vendor instructions/.test(a)) return action;
  if (a.includes("discontinue use")) return "Apply the vendor's update or mitigation. If there isn't one, stop using the product.";
  return "Apply the vendor's update or mitigation.";
}

/** Parse FIRST's EPSS CSV (comment line "#model_version…,score_date:…", header "cve,epss,percentile"). */
export function parseEpssCsv(csv: string, wanted?: ReadonlySet<string>): { date: string | null; scores: Map<string, { epss: number; percentile: number }> } {
  const scores = new Map<string, { epss: number; percentile: number }>();
  let date: string | null = null;
  for (const line of csv.split("\n")) {
    if (line.startsWith("#")) {
      date = /score_date:(\d{4}-\d{2}-\d{2})/.exec(line)?.[1] ?? date;
      continue;
    }
    const [cve, e, p] = line.trim().split(",");
    if (!cve?.startsWith("CVE-") || (wanted && !wanted.has(cve))) continue;
    const epss = Number(e);
    const percentile = Number(p);
    if (Number.isFinite(epss) && Number.isFinite(percentile)) scores.set(cve, { epss, percentile });
  }
  return { date, scores };
}

/**
 * Build the stored document from CISA's KEV JSON and parsed EPSS scores. Throws if the KEV data
 * looks broken, so a bad download never replaces good data.
 */
export function buildKevDocument(
  kev: unknown,
  epss: { date: string | null; scores: ReadonlyMap<string, { epss: number; percentile: number }> },
  now = new Date(),
): KevDocument {
  const k = kev as { catalogVersion?: unknown; vulnerabilities?: unknown };
  if (!Array.isArray(k.vulnerabilities)) throw new Error("KEV: no vulnerabilities array");
  const entries: KevEntry[] = [];
  for (const raw of k.vulnerabilities as RawKev[]) {
    const cve = text(raw.cveID);
    const score = epss.scores.get(cve);
    const entry = {
      cve,
      vendor: text(raw.vendorProject),
      product: text(raw.product),
      name: text(raw.vulnerabilityName),
      added: text(raw.dateAdded),
      description: text(raw.shortDescription),
      action: plainAction(text(raw.requiredAction)),
      due: text(raw.dueDate),
      ransomware: text(raw.knownRansomwareCampaignUse).toLowerCase() === "known",
      advisory: firstAdvisory(raw.notes),
      ...(score && { epss: score.epss, percentile: score.percentile }),
    };
    const parsed = KevEntrySchema.safeParse(entry);
    if (parsed.success) entries.push(parsed.data);
  }
  if (entries.length < KEV_MIN_ENTRIES) throw new Error(`KEV: only ${entries.length} valid entries`);
  entries.sort((a, b) => (a.added === b.added ? b.cve.localeCompare(a.cve) : b.added.localeCompare(a.added)));
  return { updatedAt: now.toISOString(), catalogVersion: text(k.catalogVersion), epssDate: epss.date, entries };
}

/** The same document with only entries added in the last RECENT_DAYS. */
export function recentKev(doc: KevDocument, now = new Date(doc.updatedAt)): KevDocument {
  const cutoff = new Date(now.getTime() - RECENT_DAYS * 86_400_000).toISOString().slice(0, 10);
  return { ...doc, entries: doc.entries.filter((e) => e.added >= cutoff) };
}

/** Case-insensitive match on vendor, product, CVE ID or name: the Intel tab's search box. */
export function matchesKev(e: KevEntry, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [e.vendor, e.product, e.cve, e.name].some((f) => f.toLowerCase().includes(q));
}

/** Products an account can watch for new known exploited vulnerabilities. */
export const MAX_WATCHES = 25;

/** Watch a vendor (all its products, product null) or one product, by KEV's own names. */
export const WatchSchema = z.strictObject({
  vendor: z.string().trim().min(1).max(100),
  product: z.string().trim().min(1).max(150).nullable(),
});
export type WatchInput = z.infer<typeof WatchSchema>;

export interface Watch {
  id: string;
  vendor: string;
  /** null = every product from this vendor. */
  product: string | null;
  createdAt: string;
}

export interface WatchesResponse {
  ok: true;
  watches: Watch[];
}

/** KEV names are matched case-insensitively, exactly otherwise ("Microsoft" + "Exchange Server"). */
export const watchKey = (s: string) => s.trim().toLowerCase();

export function watchMatches(w: { vendor: string; product: string | null }, e: { vendor: string; product: string }): boolean {
  return watchKey(w.vendor) === watchKey(e.vendor) && (w.product === null || watchKey(w.product) === watchKey(e.product));
}

/** Vendors and their products, as KEV names them, for the watchlist picker. Sorted, case-insensitively unique. */
export function kevVendors(entries: readonly { vendor: string; product: string }[]): { vendor: string; products: string[] }[] {
  const byVendor = new Map<string, { vendor: string; products: Map<string, string> }>();
  for (const e of entries) {
    const v = byVendor.get(watchKey(e.vendor)) ?? { vendor: e.vendor, products: new Map() };
    if (!v.products.has(watchKey(e.product))) v.products.set(watchKey(e.product), e.product); // first spelling wins
    byVendor.set(watchKey(e.vendor), v);
  }
  const sort = (a: string, b: string) => a.localeCompare(b, undefined, { sensitivity: "base" });
  return [...byVendor.values()].map((v) => ({ vendor: v.vendor, products: [...v.products.values()].sort(sort) })).sort((a, b) => sort(a.vendor, b.vendor));
}
