import { z } from "zod";
import { detect, type IndicatorKind } from "./detect.ts";
import { classifyIp, parseIp } from "./ip.ts";

/** Indicator kinds the reputation API accepts. */
export const LOOKUP_KINDS = ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"] as const;
export type LookupKind = (typeof LOOKUP_KINDS)[number];

export function isLookupKind(kind: IndicatorKind): kind is LookupKind {
  return (LOOKUP_KINDS as readonly string[]).includes(kind);
}

/** Longest indicator we'll send upstream (URLs are the long ones). */
export const MAX_INDICATOR_LENGTH = 2048;

export const LookupRequestSchema = z.strictObject({
  kind: z.enum(LOOKUP_KINDS),
  value: z.string().min(1).max(MAX_INDICATOR_LENGTH),
});
export type LookupRequest = z.infer<typeof LookupRequestSchema>;

export const SessionRequestSchema = z.strictObject({
  turnstileToken: z.string().min(1).max(4096),
});
export type SessionRequest = z.infer<typeof SessionRequestSchema>;

export type SourceId = "urlhaus" | "threatfox" | "malwarebazaar" | "safebrowsing";

export const SOURCE_LABELS: Readonly<Record<SourceId, string>> = {
  urlhaus: "URLhaus",
  threatfox: "ThreatFox",
  malwarebazaar: "MalwareBazaar",
  safebrowsing: "Google Safe Browsing",
};

/** Which shared sources can answer for each kind. */
export const SOURCES_FOR_KIND: Readonly<Record<LookupKind, readonly SourceId[]>> = {
  url: ["urlhaus", "threatfox", "safebrowsing"],
  domain: ["urlhaus", "threatfox", "safebrowsing"],
  ipv4: ["urlhaus", "threatfox"],
  ipv6: ["threatfox"],
  md5: ["malwarebazaar", "threatfox", "urlhaus"],
  sha1: ["malwarebazaar"],
  sha256: ["malwarebazaar", "threatfox", "urlhaus"],
};

/**
 * Re-check a request against our own detector, so the server only ever looks up the
 * canonical form of something the browser would also have recognised.
 * Returns the normalized value, or null if it doesn't hold up.
 */
export function canonicalIndicator(req: LookupRequest): string | null {
  const hit = detect(req.value).find((d) => d.kind === req.kind);
  if (!hit) return null;
  if (req.kind === "ipv4" || req.kind === "ipv6") {
    const ip = parseIp(hit.value);
    if (!ip || !classifyIp(ip).global) return null; // nobody has reputation for private ranges
  }
  return hit.value;
}

export type SourceStatus = "listed" | "not-listed" | "skipped" | "error";

export interface SourceFact {
  label: string;
  value: string;
}

export interface SourceResult {
  source: SourceId;
  status: SourceStatus;
  /** One plain-English line. Hedged for Safe Browsing ("Suspected …"). */
  summary: string;
  facts: SourceFact[];
  /** Public page on the source's site with more detail. */
  link?: string;
  /** ISO time the source was asked. */
  checkedAt?: string;
  /** True when served from our cache rather than asked just now. */
  cached?: boolean;
  /** True when served past its usual freshness because the live budget was spent. */
  stale?: boolean;
}

/**
 * Merged verdict. We never say "clean": absence from these lists isn't proof of safety.
 * - listed: at least one source lists it
 * - not-listed: every applicable source answered and none lists it
 * - incomplete: none lists it, but some sources were skipped or failed
 */
export type Verdict = "listed" | "not-listed" | "incomplete";

export interface LookupResponse {
  ok: true;
  kind: LookupKind;
  value: string;
  verdict: Verdict;
  sources: SourceResult[];
}

export type ApiErrorCode =
  | "challenge" // run Turnstile, POST /api/session, retry
  | "rate-limited"
  | "daily-limit"
  | "invalid"
  | "unavailable"
  | "signed-out"; // account routes: sign in again

export interface ApiError {
  ok: false;
  error: ApiErrorCode;
  /** Plain-English message safe to show as-is. */
  message: string;
  /** Present with "challenge". */
  siteKey?: string;
  /** Seconds, with "rate-limited". */
  retryAfter?: number;
}

export function mergeVerdict(sources: readonly SourceResult[]): Verdict {
  if (sources.some((s) => s.status === "listed")) return "listed";
  return sources.every((s) => s.status === "not-listed") ? "not-listed" : "incomplete";
}

/** Rate-limit identity for an address: IPv4 as-is, IPv6 grouped by /64 (one subscriber usually owns a /64). */
export function ipRateKey(address: string): string {
  const ip = parseIp(address.trim());
  if (!ip) return "unknown";
  if (ip.version === 4) return `v4:${address.trim()}`;
  const prefix = ip.value >> 64n;
  return `v6:${prefix.toString(16).padStart(16, "0")}/64`;
}

/** Hex SHA-256 of a string. Used for cache keys and counters so raw indicators and IPs are never stored. */
export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** KV key for an indicator's cached verdicts. Bump the version prefix when the stored shape changes. */
export async function cacheKey(kind: LookupKind, value: string): Promise<string> {
  return `v1:${await sha256Hex(`${kind}:${value}`)}`;
}
