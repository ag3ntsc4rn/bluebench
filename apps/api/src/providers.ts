import type { LookupKind, SourceFact, SourceId, SourceResult } from "@bluebench/shared";
import type { Env } from "./env.ts";

/** A provider's answer before we add cache metadata. */
export type ProviderAnswer = Omit<SourceResult, "source" | "checkedAt" | "cached" | "stale"> & {
  status: "listed" | "not-listed";
  /** How long this answer may be shown, in seconds. 0 = don't cache. */
  maxAgeSeconds?: number;
};

export class ProviderError extends Error {}

const UPSTREAM_TIMEOUT_MS = 5000;
const SAFE_BROWSING_ADVISORY = "https://developers.google.com/safe-browsing/v4/advisory";

interface Provider {
  /** False when the server lacks the source's key: the source is skipped, not failed. */
  configured(env: Env): boolean;
  query(env: Env, kind: LookupKind, value: string): Promise<ProviderAnswer>;
}

type Json = Record<string, unknown>;

async function postJson(url: string, init: RequestInit): Promise<Json> {
  let res: Response;
  try {
    res = await fetch(url, { ...init, method: "POST", signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) });
  } catch {
    throw new ProviderError("unreachable");
  }
  if (!res.ok) throw new ProviderError(`HTTP ${res.status}`);
  try {
    const data: unknown = await res.json();
    if (typeof data !== "object" || data === null) throw new Error();
    return data as Json;
  } catch {
    throw new ProviderError("bad response");
  }
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() ? v.trim() : undefined);
const list = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

function facts(...pairs: [string, unknown][]): SourceFact[] {
  return pairs.flatMap(([label, v]) => {
    const value = typeof v === "number" ? String(v) : Array.isArray(v) ? list(v).join(", ") : str(v);
    return value ? [{ label, value }] : [];
  });
}

/** abuse.ch timestamps look like "2024-01-02 03:04:05 UTC"; keep the date. */
const day = (v: unknown) => str(v)?.slice(0, 10);

function abuseChForm(env: Env, fields: Record<string, string>): RequestInit {
  return { headers: { "Auth-Key": env.ABUSECH_AUTH_KEY! }, body: new URLSearchParams(fields) };
}

function checkAbuseChStatus(data: Json, notFound: string[]): "ok" | "not-found" {
  const status = data.query_status;
  if (status === "ok") return "ok";
  if (typeof status === "string" && notFound.includes(status)) return "not-found";
  throw new ProviderError(`query_status ${String(status)}`);
}

const NOT_LISTED = (name: string): ProviderAnswer => ({ status: "not-listed", summary: `Not in ${name}.`, facts: [] });

const urlhaus: Provider = {
  configured: (env) => Boolean(env.ABUSECH_AUTH_KEY),
  async query(env, kind, value) {
    const base = "https://urlhaus-api.abuse.ch/v1";
    if (kind === "url") {
      const data = await postJson(`${base}/url/`, abuseChForm(env, { url: value }));
      if (checkAbuseChStatus(data, ["no_results", "invalid_url"]) === "not-found") return NOT_LISTED("URLhaus");
      const online = data.url_status === "online";
      return {
        status: "listed",
        summary: `Listed as a malware distribution URL${online ? ", still online" : ""}.`,
        facts: facts(["Status", data.url_status], ["Threat", data.threat], ["Tags", data.tags], ["Added", day(data.date_added)]),
        link: str(data.urlhaus_reference),
      };
    }
    if (kind === "domain" || kind === "ipv4") {
      const data = await postJson(`${base}/host/`, abuseChForm(env, { host: value }));
      if (checkAbuseChStatus(data, ["no_results", "invalid_host"]) === "not-found") return NOT_LISTED("URLhaus");
      const count = Number(data.url_count) || 0;
      const online = Array.isArray(data.urls) ? data.urls.filter((u) => (u as Json)?.url_status === "online").length : 0;
      const bl = (data.blacklists ?? {}) as Json;
      return {
        status: "listed",
        summary: `Hosted ${count} known malware URL${count === 1 ? "" : "s"}${online ? `, ${online} still online` : ""}.`,
        facts: facts(
          ["Malware URLs", count],
          ["First seen", day(data.firstseen)],
          ["Spamhaus DBL", bl.spamhaus_dbl !== "not listed" ? bl.spamhaus_dbl : undefined],
          ["SURBL", bl.surbl !== "not listed" ? bl.surbl : undefined],
        ),
        link: str(data.urlhaus_reference),
      };
    }
    const field = kind === "md5" ? "md5_hash" : "sha256_hash";
    const data = await postJson(`${base}/payload/`, abuseChForm(env, { [field]: value }));
    if (checkAbuseChStatus(data, ["no_results"]) === "not-found") return NOT_LISTED("URLhaus");
    return {
      status: "listed",
      summary: "Seen as a malware payload delivered from URLhaus-listed URLs.",
      facts: facts(
        ["Signature", data.signature],
        ["File type", data.file_type],
        ["Delivered from", Number(data.url_count) ? `${Number(data.url_count)} URLs` : undefined],
        ["First seen", day(data.firstseen)],
      ),
      link: str(data.sha256_hash) && `https://urlhaus.abuse.ch/browse.php?search=${str(data.sha256_hash)}`,
    };
  },
};

const threatfox: Provider = {
  configured: (env) => Boolean(env.ABUSECH_AUTH_KEY),
  async query(env, kind, value) {
    const isHash = kind === "md5" || kind === "sha256";
    const body = isHash ? { query: "search_hash", hash: value } : { query: "search_ioc", search_term: value };
    const data = await postJson("https://threatfox-api.abuse.ch/api/v1/", {
      headers: { "Auth-Key": env.ABUSECH_AUTH_KEY!, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (checkAbuseChStatus(data, ["no_result", "no_results", "illegal_hash", "illegal_search_term"]) === "not-found") {
      return NOT_LISTED("ThreatFox");
    }
    let iocs = (Array.isArray(data.data) ? data.data : []) as Json[];
    // search_ioc is a substring match, and IPs are stored as ip:port. Keep exact hits only.
    if (!isHash) {
      const v = value.toLowerCase();
      iocs = iocs.filter((i) => {
        const ioc = str(i.ioc)?.toLowerCase();
        return ioc === v || (kind === "ipv4" || kind === "ipv6" ? ioc?.startsWith(`${v}:`) : false);
      });
    }
    if (iocs.length === 0) return NOT_LISTED("ThreatFox");
    const top = iocs[0]!;
    const malware = [...new Set(iocs.map((i) => str(i.malware_printable)).filter(Boolean))];
    return {
      status: "listed",
      summary: `${isHash ? "Linked to" : "Listed as"} ${str(top.threat_type_desc) ?? "an indicator of compromise"}${
        malware.length ? ` (${malware.slice(0, 3).join(", ")})` : ""
      }.`,
      facts: facts(
        ["Malware", malware.slice(0, 5)],
        ["Confidence", typeof top.confidence_level === "number" ? `${top.confidence_level}%` : undefined],
        ["First seen", day(top.first_seen)],
        ["Matches", iocs.length > 1 ? iocs.length : undefined],
        ["Tags", list(top.tags).slice(0, 8)],
      ),
      link: typeof top.id === "string" || typeof top.id === "number" ? `https://threatfox.abuse.ch/ioc/${top.id}/` : undefined,
    };
  },
};

const malwarebazaar: Provider = {
  configured: (env) => Boolean(env.ABUSECH_AUTH_KEY),
  async query(env, _kind, value) {
    const data = await postJson("https://mb-api.abuse.ch/api/v1/", abuseChForm(env, { query: "get_info", hash: value }));
    if (checkAbuseChStatus(data, ["hash_not_found", "no_results", "illegal_hash"]) === "not-found") {
      return NOT_LISTED("MalwareBazaar");
    }
    const sample = ((Array.isArray(data.data) ? data.data[0] : undefined) ?? {}) as Json;
    const sha256 = str(sample.sha256_hash);
    return {
      status: "listed",
      summary: `Known malware sample${str(sample.signature) ? ` (${str(sample.signature)})` : ""}.`,
      facts: facts(
        ["Signature", sample.signature],
        ["File type", sample.file_type],
        ["File name", sample.file_name],
        ["First seen", day(sample.first_seen)],
        ["Tags", list(sample.tags).slice(0, 8)],
        ["SHA-256", sha256],
      ),
      link: sha256 && `https://bazaar.abuse.ch/sample/${sha256}/`,
    };
  },
};

/** Hedged wording, as Google's terms require. */
const THREAT_WORDING: Record<string, string> = {
  SOCIAL_ENGINEERING: "Suspected phishing or deceptive site",
  MALWARE: "Possible malware site",
  UNWANTED_SOFTWARE: "Possible unwanted software",
  POTENTIALLY_HARMFUL_APPLICATION: "Possible harmful application",
};

const safebrowsing: Provider = {
  configured: (env) => Boolean(env.SAFE_BROWSING_API_KEY),
  async query(env, kind, value) {
    const url = kind === "domain" ? `http://${value}/` : value;
    const data = await postJson(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(env.SAFE_BROWSING_API_KEY!)}`,
      {
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "bluebench", clientVersion: "1.0" },
          threatInfo: {
            threatTypes: Object.keys(THREAT_WORDING),
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }],
          },
        }),
      },
    );
    const matches = (Array.isArray(data.matches) ? data.matches : []) as Json[];
    if (matches.length === 0) {
      // No cache duration is given for a non-match, so we don't cache it.
      return {
        status: "not-listed",
        summary: "No current warning. Safe Browsing protection isn't perfect, so this isn't a guarantee.",
        facts: [],
        link: SAFE_BROWSING_ADVISORY,
        maxAgeSeconds: 0,
      };
    }
    const types = [...new Set(matches.map((m) => str(m.threatType)).filter((t): t is string => Boolean(t)))];
    // Obey the shortest cache duration exactly ("300s").
    const durations = matches.map((m) => parseFloat(str(m.cacheDuration) ?? "0")).filter((n) => n > 0);
    return {
      status: "listed",
      summary: `${THREAT_WORDING[types[0]!] ?? "Possible unsafe site"}. Advisory provided by Google.`,
      facts: facts(["Warnings", types.map((t) => THREAT_WORDING[t] ?? t)]),
      link: SAFE_BROWSING_ADVISORY,
      maxAgeSeconds: durations.length ? Math.floor(Math.min(...durations)) : 0,
    };
  },
};

export const PROVIDERS: Readonly<Record<SourceId, Provider>> = { urlhaus, threatfox, malwarebazaar, safebrowsing };
