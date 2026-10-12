import { z } from "zod";
import { LOOKUP_KINDS, MAX_INDICATOR_LENGTH, type LookupKind, type SourceFact, type SourceResult } from "./lookup.ts";

/**
 * Bring-your-own-key sources. The user's key is stored only in their browser and sent only to the
 * provider. OTX allows cross-site calls, so the browser asks it directly. VirusTotal, AbuseIPDB and
 * GreyNoise don't, so those go through our relay (POST /api/byo), which passes the request on and
 * returns the parsed answer without logging, storing or caching the key, the indicator or the result.
 *
 * Request builders and parsers live here so the browser and the relay read answers the same way.
 */
export type ByoSourceId = "virustotal" | "abuseipdb" | "greynoise" | "otx";

export interface ByoSource {
  label: string;
  /** Indicator kinds the source can answer. */
  kinds: readonly LookupKind[];
  /** True if it must go through our relay (no CORS). */
  relay: boolean;
  /** Where a user gets a free key. */
  keyUrl: string;
  /** One line on the free plan's limits. */
  limits: string;
}

const HASHES = ["md5", "sha1", "sha256"] as const;

export const BYO_SOURCES: Readonly<Record<ByoSourceId, ByoSource>> = {
  virustotal: {
    label: "VirusTotal",
    kinds: ["ipv4", "ipv6", "domain", "url", ...HASHES],
    relay: true,
    keyUrl: "https://www.virustotal.com/gui/my-apikey",
    limits: "Free keys: 4 lookups a minute, 500 a day, non-commercial use.",
  },
  abuseipdb: {
    label: "AbuseIPDB",
    kinds: ["ipv4", "ipv6"],
    relay: true,
    keyUrl: "https://www.abuseipdb.com/account/api",
    limits: "Free keys: 1,000 checks a day.",
  },
  greynoise: {
    label: "GreyNoise",
    kinds: ["ipv4"],
    relay: true,
    keyUrl: "https://viz.greynoise.io/account/api-key",
    limits: "Community keys: a small daily allowance of IP lookups.",
  },
  otx: {
    label: "AlienVault OTX",
    kinds: ["ipv4", "ipv6", "domain", "url", ...HASHES],
    relay: false,
    keyUrl: "https://otx.alienvault.com/api",
    limits: "Free keys: generous limits for personal use.",
  },
};

export const BYO_SOURCE_IDS = Object.keys(BYO_SOURCES) as ByoSourceId[];
export const RELAY_SOURCE_IDS = BYO_SOURCE_IDS.filter((s) => BYO_SOURCES[s].relay);

/** API keys are opaque tokens; this rejects anything that could smuggle extra headers or paths. */
export const ByoKeySchema = z.string().regex(/^[A-Za-z0-9_-]{16,128}$/, "That doesn't look like an API key.");

export const ByoRequestSchema = z.strictObject({
  kind: z.enum(LOOKUP_KINDS),
  value: z.string().min(1).max(MAX_INDICATOR_LENGTH),
  keys: z
    .strictObject({ virustotal: ByoKeySchema.optional(), abuseipdb: ByoKeySchema.optional(), greynoise: ByoKeySchema.optional() })
    .refine((k) => Object.values(k).some(Boolean), "No keys given"),
});
export type ByoRequest = z.infer<typeof ByoRequestSchema>;

export interface ByoResponse {
  ok: true;
  sources: SourceResult[];
}

/** Sources the user has a key for that can answer this kind. */
export const byoSourcesFor = (kind: LookupKind, keys: Partial<Record<ByoSourceId, string>>) =>
  BYO_SOURCE_IDS.filter((s) => keys[s] && BYO_SOURCES[s].kinds.includes(kind));

function base64url(text: string): string {
  let bin = "";
  for (const b of new TextEncoder().encode(text)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const isIp = (k: LookupKind) => k === "ipv4" || k === "ipv6";
const isHash = (k: LookupKind) => (HASHES as readonly string[]).includes(k);

const VT_PATH = (kind: LookupKind) => (isIp(kind) ? "ip_addresses" : kind === "domain" ? "domains" : kind === "url" ? "urls" : "files");
const OTX_SECTION = (kind: LookupKind) => (kind === "ipv4" ? "IPv4" : kind === "ipv6" ? "IPv6" : kind === "domain" ? "domain" : kind === "url" ? "url" : "file");

/** The provider request for an indicator. `value` must already be canonical (see canonicalIndicator). */
export function byoRequest(source: ByoSourceId, kind: LookupKind, value: string, key: string): { url: string; headers: Record<string, string> } {
  const v = encodeURIComponent(value);
  switch (source) {
    case "virustotal":
      return {
        url: `https://www.virustotal.com/api/v3/${VT_PATH(kind)}/${kind === "url" ? base64url(value) : v}`,
        headers: { "x-apikey": key, accept: "application/json" },
      };
    case "abuseipdb":
      return { url: `https://api.abuseipdb.com/api/v2/check?ipAddress=${v}&maxAgeInDays=90`, headers: { Key: key, Accept: "application/json" } };
    case "greynoise":
      return { url: `https://api.greynoise.io/v3/community/${v}`, headers: { key, accept: "application/json" } };
    case "otx":
      return { url: `https://otx.alienvault.com/api/v1/indicators/${OTX_SECTION(kind)}/${v}/general`, headers: { "X-OTX-API-KEY": key } };
  }
}

/** Hosts the relay may call. Anything else is refused. */
export const RELAY_HOSTS: ReadonlySet<string> = new Set(["www.virustotal.com", "api.abuseipdb.com", "api.greynoise.io"]);

type Json = Record<string, unknown>;
const obj = (v: unknown): Json => (v && typeof v === "object" && !Array.isArray(v) ? (v as Json) : {});
const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : 0);
const str = (v: unknown) => (typeof v === "string" && v.trim() ? v.trim() : undefined);
const day = (v: unknown) => {
  if (typeof v === "number" && v > 0) return new Date(v * 1000).toISOString().slice(0, 10);
  const s = str(v);
  return s ? s.slice(0, 10) : undefined;
};
function facts(...rows: [string, unknown][]): SourceFact[] {
  return rows.flatMap(([label, value]) => (value === undefined || value === null || value === "" ? [] : [{ label, value: String(value) }]));
}

type Parsed = Omit<SourceResult, "source">;

/** What to say when the provider answered with an error status. */
export function byoHttpError(source: ByoSourceId, status: number): Parsed {
  const label = BYO_SOURCES[source].label;
  if (status === 401 || status === 403) return { status: "error", summary: `${label} didn't accept your API key. Check it in Settings.`, facts: [] };
  if (status === 429) return { status: "skipped", summary: `Your ${label} key has used up its quota for now. ${BYO_SOURCES[source].limits}`, facts: [] };
  return { status: "error", summary: `${label} answered with an error (${status}). Try again shortly.`, facts: [] };
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

/**
 * Turn a provider's answer into a source result. `status` is the HTTP status, `body` the parsed JSON
 * (or null). Never throws.
 */
export function parseByo(source: ByoSourceId, kind: LookupKind, value: string, status: number, body: unknown): Parsed {
  const label = BYO_SOURCES[source].label;
  const notFound = (summary = `Not in ${label}.`): Parsed => ({ status: "not-listed", summary, facts: [] });

  switch (source) {
    case "virustotal": {
      if (status === 404) return notFound(`${label} has no record of this.`);
      if (status !== 200) return byoHttpError(source, status);
      const data = obj(obj(body).data);
      const a = obj(data.attributes);
      const stats = obj(a.last_analysis_stats);
      const malicious = num(stats.malicious);
      const suspicious = num(stats.suspicious);
      const total = malicious + suspicious + num(stats.harmless) + num(stats.undetected);
      const gui = isIp(kind) ? "ip-address" : kind === "domain" ? "domain" : kind === "url" ? "url" : "file";
      const id = str(data.id) ?? value;
      const result = facts(
        ["Engines", total ? `${malicious} malicious, ${suspicious} suspicious of ${total}` : undefined],
        ["Community score", a.reputation !== undefined ? num(a.reputation) : undefined],
        ["Name", isHash(kind) ? str(a.meaningful_name) : undefined],
        ["Last analysed", day(a.last_analysis_date)],
      );
      const link = `https://www.virustotal.com/gui/${gui}/${encodeURIComponent(id)}`;
      // A single engine's detection is often a false positive, so it takes two to call it listed.
      if (malicious >= 2) return { status: "listed", summary: `${plural(malicious, "security vendor")} of ${total} flag this as malicious.`, facts: result, link };
      const summary =
        malicious === 1 ? `1 vendor of ${total} flags this as malicious. A single detection is often a false positive.` : total ? `No vendor flags this as malicious (${total} checked).` : `${label} has no analysis yet.`;
      return { status: "not-listed", summary, facts: result, link };
    }

    case "abuseipdb": {
      if (status !== 200) return byoHttpError(source, status);
      const d = obj(obj(body).data);
      const score = num(d.abuseConfidenceScore);
      const reports = num(d.totalReports);
      const result = facts(
        ["Abuse confidence", `${score}%`],
        ["Reports (90 days)", reports],
        ["Last reported", day(d.lastReportedAt)],
        ["ISP", str(d.isp)],
        ["Usage", str(d.usageType)],
        ["Country", str(d.countryCode)],
      );
      const link = `https://www.abuseipdb.com/check/${encodeURIComponent(value)}`;
      if (d.isWhitelisted === true) return { status: "not-listed", summary: `${label} lists this as a known, trusted address.`, facts: result, link };
      if (score >= 25) return { status: "listed", summary: `Reported for abuse ${plural(reports, "time")} in 90 days, with ${score}% confidence.`, facts: result, link };
      return {
        status: "not-listed",
        summary: reports ? `${plural(reports, "report")} in 90 days, but a low confidence score (${score}%).` : "No abuse reports in the last 90 days.",
        facts: result,
        link,
      };
    }

    case "greynoise": {
      if (status === 404) return notFound(`${label} hasn't seen this address scanning the internet, and it isn't a known business service.`);
      if (status !== 200) return byoHttpError(source, status);
      const b = obj(body);
      const classification = str(b.classification) ?? "unknown";
      const result = facts(["Classification", classification], ["Name", b.name !== "unknown" ? str(b.name) : undefined], ["Last seen", day(b.last_seen)]);
      const link = str(b.link) ?? `https://viz.greynoise.io/ip/${encodeURIComponent(value)}`;
      if (classification === "malicious") return { status: "listed", summary: "Seen scanning or attacking the internet, classified malicious.", facts: result, link };
      if (b.riot === true || classification === "benign") {
        return { status: "not-listed", summary: `A known benign service${str(b.name) && b.name !== "unknown" ? ` (${str(b.name)})` : ""}.`, facts: result, link };
      }
      return { status: "not-listed", summary: b.noise === true ? "Seen scanning the internet, not classified malicious." : "Not seen scanning the internet.", facts: result, link };
    }

    case "otx": {
      if (status === 404 || status === 400) return notFound(`${label} has no record of this.`);
      if (status !== 200) return byoHttpError(source, status);
      const b = obj(body);
      const pulses = obj(b.pulse_info);
      const count = num(pulses.count);
      const names = (Array.isArray(pulses.pulses) ? pulses.pulses : []).map((p) => str(obj(p).name)).filter(Boolean).slice(0, 3);
      const known = (Array.isArray(b.validation) ? b.validation : []).map((v) => str(obj(v).message) ?? str(obj(v).name)).filter(Boolean);
      const gui = isIp(kind) ? "ip" : kind === "domain" ? "domain" : kind === "url" ? "url" : "file";
      const link = `https://otx.alienvault.com/indicator/${gui}/${encodeURIComponent(value)}`;
      const result = facts(["Pulses", count], ["Recent pulses", names.length ? names.join("; ") : undefined], ["Known good", known.length ? known.join("; ") : undefined]);
      // Popular sites appear in many pulses (as references); OTX's validation marks them as known good.
      if (known.length > 0) return { status: "not-listed", summary: `${label} marks this as known good, even though it appears in ${plural(count, "pulse")}.`, facts: result, link };
      if (count > 0) return { status: "listed", summary: `Appears in ${plural(count, "community threat pulse")}.`, facts: result, link };
      return { status: "not-listed", summary: "Not in any community threat pulse.", facts: result, link };
    }
  }
}
