import { CHECK_LABELS, KIND_LABELS, SOURCE_LABELS, type DomainReport, type LookupResponse, type SourceStatus } from "@bluebench/shared";
import type { HeaderAnalysis } from "./email-headers";
import type { Finding } from "./findings";
import { formatUtc, sortFindings } from "./findings";
import type { DecodedJwt } from "./jwt";
import type { UrlAnalysis } from "./url";

/**
 * Plain-text summaries for the "Copy result" button: tidy enough to paste into a ticket, chat or
 * incident note. Suspicious indicators are defanged so they don't become clickable links when shared.
 */

const FOOTER = "via bluebench.dev";

/** example.com → example[.]com, 192.0.2.1 → 192[.]0[.]2[.]1 */
export const defangHost = (host: string) => host.replace(/\./g, "[.]");

/** https://evil.example/a.php → hxxps://evil[.]example/a[.]php */
export function defangUrl(href: string): string {
  try {
    const u = new URL(href);
    const scheme = u.protocol.replace(/^http/i, "hxxp").replace(/:$/, "");
    const host = u.hostname.startsWith("[") ? u.hostname : defangHost(u.hostname);
    const auth = u.username ? `${u.username}${u.password ? `:${u.password}` : ""}@` : "";
    // Path and query are defanged too: redirect parameters often carry a second (percent-encoded) URL.
    return `${scheme}://${auth}${host}${u.port ? `:${u.port}` : ""}${defangText(href.slice(href.indexOf(u.host) + u.host.length))}`;
  } catch {
    return href.replace(/^http/i, "hxxp").replace(/\./g, "[.]");
  }
}

/**
 * Neutralise indicators inside free text (findings, subjects, decoded parameters): http(s) schemes,
 * domain names and IPv4 addresses. Errs on the side of defanging (a file name like a.php becomes a[.]php).
 */
export function defangText(text: string): string {
  return text
    .replace(/\bhttp(s?):\/\//gi, "hxxp$1://")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, (ip) => defangHost(ip))
    .replace(/\b(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*[a-z]\b/gi, (name) => defangHost(name));
}

/** email: user@evil.example → user@evil[.]example */
export const defangEmail = (address: string) => {
  const at = address.lastIndexOf("@");
  return at < 0 ? defangHost(address) : `${address.slice(0, at)}@${defangHost(address.slice(at + 1))}`;
};

const SEVERITY_WORD: Record<Finding["severity"], string> = { critical: "Red flag", warning: "Warning", info: "Note" };

function findingLines(findings: Finding[], empty: string): string[] {
  if (findings.length === 0) return [`- ${empty}`];
  return sortFindings(findings).map((f) => defangText(`- ${SEVERITY_WORD[f.severity]}: ${f.title}${f.detail ? ` (${f.detail})` : ""}`));
}

const STATUS_WORD: Record<SourceStatus, string> = { listed: "Listed", "not-listed": "Not listed", skipped: "Skipped", error: "Error" };
const VERDICT_WORD = { listed: "Listed by at least one source", "not-listed": "Not listed by any source", incomplete: "Not listed (some sources unavailable)" };

export function summarizeLookup(r: LookupResponse, now = Date.now()): string {
  const value = r.kind === "url" ? defangUrl(r.value) : r.kind.startsWith("ip") || r.kind === "domain" ? defangHost(r.value) : r.value;
  const lines = [`Reputation: ${value} (${KIND_LABELS[r.kind]})`, `Verdict: ${VERDICT_WORD[r.verdict]}`, ""];
  for (const s of r.sources) {
    const status = s.source === "safebrowsing" && s.status === "listed" ? "Suspected" : STATUS_WORD[s.status];
    lines.push(`- ${SOURCE_LABELS[s.source]}: ${status}. ${s.summary}`);
    for (const f of s.facts) lines.push(`    ${f.label}: ${f.value}`);
    if (s.link && s.source !== "safebrowsing") lines.push(`    ${s.link}`);
  }
  if (r.sources.some((s) => s.source === "safebrowsing" && s.status !== "skipped")) {
    lines.push("", "Safe Browsing: Advisory provided by Google. Protection isn't perfect: some unsafe sites may not be identified.");
  }
  lines.push("", `Checked ${formatUtc(now)}, ${FOOTER}. Indicators defanged for safe sharing.`);
  return lines.join("\n");
}

const CHECK_WORD = { pass: "Pass", warn: "Warning", fail: "Fail", info: "Info", skipped: "Skipped" } as const;
const ORDER = { fail: 0, warn: 1, pass: 2, info: 3, skipped: 4 } as const;

export function summarizeDomain(r: DomainReport): string {
  const lines = [`Domain report: ${r.domain}`, `Grade: ${r.grade} (${r.score}/100)`, ""];
  for (const c of [...r.checks].sort((a, b) => ORDER[a.status] - ORDER[b.status])) {
    lines.push(`- ${CHECK_LABELS[c.id]}: ${CHECK_WORD[c.status]}. ${c.summary}`);
    if (c.fix) lines.push(`    Fix: ${c.fix}`);
  }
  lines.push("", `Checked ${formatUtc(Date.parse(r.checkedAt))}, ${FOOTER}.`);
  return lines.join("\n");
}

export function summarizeHeaders(a: HeaderAnalysis, now = Date.now()): string {
  const mailbox = (m?: { display: string; address: string }) =>
    m ? `${m.display ? `"${m.display}" ` : ""}<${defangEmail(m.address)}>` : "(none)";
  const lines = ["Email header analysis", `Subject: ${a.subject ? defangText(a.subject) : "(none)"}`, `From: ${mailbox(a.from)}`];
  if (a.replyTo) lines.push(`Reply-To: ${mailbox(a.replyTo)}`);
  if (a.returnPath) lines.push(`Return-Path: ${mailbox(a.returnPath)}`);
  if (a.date) lines.push(`Date: ${a.date}`);
  lines.push("", "Authentication:");
  if (a.auth.length === 0) lines.push("- No authentication results in these headers");
  for (const r of a.auth) lines.push(`- ${r.method.toUpperCase()}: ${r.result}${r.domain ? ` (${defangHost(r.domain)})` : ""}`);
  lines.push("", "Findings:", ...findingLines(a.findings, "Nothing unusual found"));
  if (a.hops.length > 0) {
    lines.push("", `Delivery path (${a.hops.length} hop${a.hops.length === 1 ? "" : "s"}${a.totalDelay ? `, ${a.totalDelay} total` : ""}):`);
    a.hops.forEach((h, i) => {
      const from = [h.from && defangHost(h.from), h.ip && `[${defangHost(h.ip)}]`].filter(Boolean).join(" ");
      lines.push(`${i + 1}. ${from || "(unknown)"} → ${h.by ? defangHost(h.by) : "(unknown)"}${h.delayDisplay ? ` (+${h.delayDisplay})` : ""}`);
    });
  }
  lines.push("", `Analysed ${formatUtc(now)} in the browser, ${FOOTER}. Addresses defanged for safe sharing.`);
  return lines.join("\n");
}

export function summarizeJwt(j: DecodedJwt): string {
  const lines = ["JWT", "", "Findings:", ...findingLines(j.findings, "Nothing unusual found")];
  if (j.times.length > 0) {
    lines.push("", "Times:");
    for (const t of j.times) lines.push(`- ${t.label} (${t.claim}): ${t.display}`);
  }
  lines.push("", "Header:", JSON.stringify(j.header, null, 2), "", "Payload:", j.payloadText ?? JSON.stringify(j.payload, null, 2));
  lines.push("", `Decoded in the browser, ${FOOTER}. Signature not verified.`);
  return lines.join("\n");
}

export function summarizeUrl(u: UrlAnalysis): string {
  const lines = [`URL: ${defangUrl(u.href)}`, `Host: ${defangHost(u.host)}${u.port ? `:${u.port}` : ""}`, "", "Findings:", ...findingLines(u.findings, "Nothing unusual in how this URL is built")];
  if (u.params.length > 0) {
    lines.push("", "Query parameters (decoded):");
    for (const [k, v] of u.params) lines.push(`- ${k} = ${v ? defangText(v) : "(empty)"}`);
  }
  lines.push("", `Analysed in the browser, ${FOOTER}. Link defanged for safe sharing; it was never visited.`);
  return lines.join("\n");
}
