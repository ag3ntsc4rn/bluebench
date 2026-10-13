import { refang } from "./detect.ts";
import { normalizeDomain } from "./domain.ts";
import { formatIPv4, formatIPv6, parseIPv4, parseIPv6 } from "./ip.ts";
import { mergeVerdict, SOURCE_LABELS, type LookupResponse, type Verdict } from "./lookup.ts";
import { TLDS } from "./tlds.ts";

/**
 * Bulk IOC extraction: pull every indicator out of pasted text (a report, an email, a log excerpt),
 * refanged and de-duplicated, then export it as CSV or STIX 2.1. Pure; runs in the browser.
 */

export type ExtractedKind = "ipv4" | "ipv6" | "domain" | "url" | "email" | "md5" | "sha1" | "sha256";

export interface Extracted {
  kind: ExtractedKind;
  /** Refanged and normalized. */
  value: string;
}

/** Most indicators returned from one paste. */
export const MAX_EXTRACTED = 1000;

/**
 * Real TLDs that are far more often file extensions in reports ("README.md", "run.sh", "ld.so", "main.rs", "setup.py").
 * A bare name ending in one is treated as a file name; inside a URL it still counts. Abused TLDs that
 * are also extensions, like .zip and .mov, stay: missing a real phishing domain is worse.
 */
const FILE_LIKE_TLDS = new Set(["md", "py", "sh", "so", "rs"]);

const TRAILING = /[.,;:!?)\]}>'"]+$/;

/** Pull every indicator out of free text: refanged, normalized, de-duplicated, in order of first appearance. */
export function extractIndicators(input: string, max = MAX_EXTRACTED): Extracted[] {
  let text = refang(input);
  const out: Extracted[] = [];
  const seen = new Set<string>();
  const add = (kind: ExtractedKind, value: string) => {
    const key = `${kind}:${value}`;
    if (out.length >= max || seen.has(key)) return;
    seen.add(key);
    out.push({ kind, value });
  };
  // Blank out what's been matched, so the host inside a URL or email isn't listed again as a domain or IP.
  const consume = (re: RegExp, handle: (m: string) => void) => {
    text = text.replace(re, (m) => {
      handle(m);
      return " ".repeat(m.length);
    });
  };

  consume(/\b(?:https?|ftp):\/\/[^\s<>"'`]+/gi, (m) => {
    const raw = m.replace(TRAILING, "");
    try {
      const url = new URL(raw);
      if (url.hostname) add("url", url.href);
    } catch {
      // not a URL after all
    }
  });

  consume(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b/g, (m) => {
    const at = m.lastIndexOf("@");
    const domain = normalizeDomain(m.slice(at + 1));
    if (domain) add("email", `${m.slice(0, at)}@${domain}`);
  });

  consume(/\b[0-9a-f]{32,64}\b/gi, (m) => {
    const kind = m.length === 32 ? "md5" : m.length === 40 ? "sha1" : m.length === 64 ? "sha256" : null;
    if (kind) add(kind, m.toLowerCase());
  });

  // IPv4, but not part of a longer dotted number like a version string (1.2.3.4.5).
  consume(/(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)/g, (m) => {
    const ip = parseIPv4(m);
    if (ip !== null) add("ipv4", formatIPv4(ip));
  });

  consume(/(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])/gi, (m) => {
    if (!m.includes("::") && m.split(":").length !== 8) return; // times like 12:30:45 aren't addresses
    const ip = parseIPv6(m);
    if (ip !== null) add("ipv6", formatIPv6(ip));
  });

  consume(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b/gi, (m) => {
    const rawTld = m.slice(m.lastIndexOf(".") + 1);
    // "…the end.Then…": a mixed-case ending is a missing space after a full stop, not a TLD.
    if (/[A-Z]/.test(rawTld) && /[a-z]/.test(rawTld)) return;
    const tld = rawTld.toLowerCase();
    if (!TLDS.has(tld) || FILE_LIKE_TLDS.has(tld)) return;
    const domain = normalizeDomain(m);
    if (domain) add("domain", domain);
  });

  // Grouped by kind; within a kind, in order of first appearance (sort is stable).
  const order: ExtractedKind[] = ["url", "domain", "ipv4", "ipv6", "email", "sha256", "sha1", "md5"];
  return out.sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind));
}

/** Key for an extracted item, used to attach its reputation result. */
export const extractedKey = (i: Extracted) => `${i.kind}:${i.value}`;

/**
 * A reputation result as it may be exported. Google forbids showing Safe Browsing verdicts past their
 * cache duration, and a downloaded file keeps them indefinitely, so exports are worked out without it.
 */
export interface ExportVerdict {
  verdict: Verdict;
  /** Sources that list it (never Safe Browsing). */
  listedBy: string[];
}
export type ExportVerdicts = ReadonlyMap<string, ExportVerdict>;

export function exportVerdict(res: Pick<LookupResponse, "sources">): ExportVerdict {
  const sources = res.sources.filter((s) => s.source !== "safebrowsing");
  return {
    verdict: sources.length > 0 ? mergeVerdict(sources) : "incomplete",
    listedBy: sources.filter((s) => s.status === "listed").map((s) => SOURCE_LABELS[s.source]),
  };
}

/** Spreadsheet apps run cells starting with these as formulas; prefix a quote so they stay text. */
function csvCell(value: string): string {
  const safe = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

/**
 * CSV with a header row. `defang` produces the share-safe form of each value. The verdict column is
 * empty for items not checked; it never reflects Safe Browsing (see ExportVerdict).
 */
export function toCsv(items: readonly Extracted[], defang: (item: Extracted) => string, verdicts: ExportVerdicts = new Map()): string {
  const rows = [
    ["type", "value", "defanged", "verdict", "listed_by"],
    ...items.map((i) => {
      const v = verdicts.get(extractedKey(i));
      return [i.kind, i.value, defang(i), v?.verdict ?? "", v?.listedBy.join("; ") ?? ""];
    }),
  ];
  return rows.map((r) => r.map(csvCell).join(",")).join("\r\n") + "\r\n";
}

/** STIX 2.1 pattern for one indicator. Values are quoted with backslash and quote escaped. */
export function stixPattern(item: Extracted): string {
  const q = `'${item.value.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
  switch (item.kind) {
    case "ipv4":
      return `[ipv4-addr:value = ${q}]`;
    case "ipv6":
      return `[ipv6-addr:value = ${q}]`;
    case "domain":
      return `[domain-name:value = ${q}]`;
    case "url":
      return `[url:value = ${q}]`;
    case "email":
      return `[email-addr:value = ${q}]`;
    case "md5":
      return `[file:hashes.MD5 = ${q}]`;
    case "sha1":
      return `[file:hashes.'SHA-1' = ${q}]`;
    case "sha256":
      return `[file:hashes.'SHA-256' = ${q}]`;
  }
}

/**
 * A STIX 2.1 bundle with one indicator per item. Items a checked source lists get indicator_types
 * ["malicious-activity"] and a description naming the sources; others imply no verdict. `uuid` is
 * injectable for tests.
 */
export function toStixBundle(
  items: readonly Extracted[],
  now = new Date(),
  uuid: () => string = () => crypto.randomUUID(),
  verdicts: ExportVerdicts = new Map(),
): string {
  const ts = now.toISOString();
  const objects = items.map((item) => {
    const v = verdicts.get(extractedKey(item));
    const listed = v?.verdict === "listed";
    return {
      type: "indicator",
      spec_version: "2.1",
      id: `indicator--${uuid()}`,
      created: ts,
      modified: ts,
      name: item.value,
      ...(listed && {
        description: `Listed by ${v.listedBy.join(", ")} (checked with Bluebench on ${ts.slice(0, 10)}).`,
        indicator_types: ["malicious-activity"],
      }),
      pattern: stixPattern(item),
      pattern_type: "stix",
      pattern_version: "2.1",
      valid_from: ts,
    };
  });
  return JSON.stringify({ type: "bundle", id: `bundle--${uuid()}`, objects }, null, 2);
}
