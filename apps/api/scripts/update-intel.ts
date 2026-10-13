/**
 * Build the Intel tab's data: CISA KEV (CC0) joined with FIRST EPSS scores (free; attribution requested).
 * Run by .github/workflows/intel.yml twice a day; writes recent.json, all.json and vendors.json to the given folder,
 * which the workflow then stores in KV (see KEV_KV_KEYS). Nothing is deployed.
 *
 *   node apps/api/scripts/update-intel.ts <out-dir>
 *
 * Fails (non-zero exit) without writing anything if KEV looks broken, so bad data never replaces good.
 * EPSS is optional: if it can't be fetched, the entries go out without scores.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { buildKevDocument, EPSS_SOURCE_URL, KEV_SOURCE_URL, KevDocumentSchema, kevVendors, parseEpssCsv, recentKev } from "@bluebench/shared";

const UA = { "user-agent": "Bluebench/1.0 (+https://bluebench.dev)" };
const out = process.argv[2];
if (!out) throw new Error("usage: update-intel.ts <out-dir>");

const kevRes = await fetch(KEV_SOURCE_URL, { headers: UA, signal: AbortSignal.timeout(60_000) });
if (!kevRes.ok) throw new Error(`KEV download failed: HTTP ${kevRes.status}`);
const kev = (await kevRes.json()) as { vulnerabilities?: { cveID?: string }[] };
const wanted = new Set((kev.vulnerabilities ?? []).map((v) => v.cveID ?? ""));

// FIRST asks bulk users to take the daily CSV rather than call the API per CVE.
let epss: ReturnType<typeof parseEpssCsv> = { date: null, scores: new Map() };
try {
  const res = await fetch(EPSS_SOURCE_URL, { headers: UA, redirect: "follow", signal: AbortSignal.timeout(120_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  epss = parseEpssCsv(gunzipSync(Buffer.from(await res.arrayBuffer())).toString("utf8"), wanted);
} catch (e) {
  console.warn(`EPSS unavailable, continuing without scores: ${(e as Error).message}`);
}

const all = KevDocumentSchema.parse(buildKevDocument(kev, epss));
const recent = recentKev(all);
mkdirSync(out, { recursive: true });
// Stored exactly as GET /api/intel/kev returns them (a KevResponse), so the Worker never parses them.
writeFileSync(join(out, "all.json"), JSON.stringify({ ok: true, ...all }));
writeFileSync(join(out, "recent.json"), JSON.stringify({ ok: true, ...recent }));
writeFileSync(join(out, "vendors.json"), JSON.stringify({ ok: true, updatedAt: all.updatedAt, vendors: kevVendors(all.entries) }));
console.log(`KEV ${all.catalogVersion}: ${all.entries.length} entries (${recent.entries.length} recent), EPSS ${epss.date ?? "missing"} for ${epss.scores.size}`);
