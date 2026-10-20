import { detect, extractIndicators, orgDomain, parseIp, sniffFileType, type ExportVerdicts, type Extracted, extractedKey } from "@bluebench/shared";
import type { HeaderAnalysis } from "./email-headers";
import { formatUtc, sortFindings, type Finding } from "./findings";
import type { MimeAttachment, ParsedMessage } from "./mime";
import { defangEmail, defangExtracted, defangHost, defangText, findingLines } from "./summaries";

/**
 * Phishing triage: links, attachments, indicators, a summary of red flags and a ticket note, worked out
 * from a parsed message (lib/mime.ts). Everything here runs in the browser. Email HTML is only parsed,
 * never put into the page, so its scripts don't run and its images and resources are never loaded.
 */

// --- HTML bodies ---

export interface HtmlLink {
  href: string;
  /** Visible link text, whitespace collapsed. */
  text: string;
}

export interface HtmlContent {
  links: HtmlLink[];
  /** Visible text, for indicator extraction. */
  text: string;
}

const collapse = (s: string | null | undefined) => (s ?? "").replace(/\s+/g, " ").trim();

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
const decodeEntities = (s: string) =>
  s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (whole, e: string) => {
    if (e[0] === "#") {
      const code = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
    }
    return ENTITIES[e.toLowerCase()] ?? whole;
  });

/**
 * Links and visible text from an HTML body. Uses DOMParser, whose documents are inert: no scripts run and
 * nothing (images, stylesheets, frames) is fetched. Where there's no DOMParser (tests, pre-rendering), a
 * rough regex reading is used instead.
 */
export function readHtml(html: string): HtmlContent {
  if (typeof DOMParser !== "undefined") {
    const doc = new DOMParser().parseFromString(html, "text/html");
    doc.querySelectorAll("script, style, noscript, template, head").forEach((e) => e.remove());
    const links = [...doc.querySelectorAll("a[href], area[href]")].map((a) => ({
      href: (a.getAttribute("href") ?? "").trim(),
      text: collapse(a.textContent),
    }));
    return { links, text: collapse(doc.body?.textContent) };
  }
  const clean = html.replace(/<(script|style|noscript|template|head)\b[\s\S]*?<\/\1\s*>/gi, " ");
  const links: HtmlLink[] = [];
  for (const m of clean.matchAll(/<a\b[^>]*?\shref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a\s*>/gi)) {
    links.push({ href: decodeEntities(m[1] ?? m[2] ?? m[3] ?? "").trim(), text: collapse(decodeEntities(m[4]!.replace(/<[^>]*>/g, " "))) });
  }
  return { links, text: collapse(decodeEntities(clean.replace(/<[^>]*>/g, " "))) };
}

// --- Links ---

export interface TriageLink {
  href: string;
  /** Visible text, for HTML links. */
  text?: string;
  source: "html" | "text";
  findings: Finding[];
}

/** Most links listed; a message with more is unusual in itself. */
export const MAX_LINKS = 300;

const SCRIPT_SCHEMES = new Set(["javascript", "vbscript", "data", "file"]);
const HARMLESS_SCHEMES = new Set(["http", "https", "mailto", "tel", "sms", "cid", "mid"]);

/** Host comparison key: the registrable domain, or the whole address for an IP. */
const hostKey = (host: string) => (parseIp(host.replace(/^\[|\]$/g, "")) ? host : orgDomain(host));

function hostOf(href: string): string | null {
  try {
    const u = new URL(href);
    return u.protocol === "http:" || u.protocol === "https:" ? u.hostname.toLowerCase() : null;
  } catch {
    return null;
  }
}

/** The host a link's visible text claims to go to, if the text is itself a URL or domain. */
export function claimedHost(text: string): string | null {
  const t = text.trim();
  if (!t || t.length > 2048 || /\s/.test(t)) return null;
  const d = detect(t).find((x) => x.kind === "url" || x.kind === "domain");
  if (!d) return null;
  return d.kind === "domain" ? d.value : hostOf(d.value);
}

/** Red flags for one link. Pure. */
export function linkFindings(href: string, text?: string): Finding[] {
  const findings: Finding[] = [];
  // Browsers ignore whitespace and control characters in a scheme ("java\tscript:"), so we do too.
  const squashed = href.replace(/[\x00-\x20]/g, "");
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(squashed)?.[1]?.toLowerCase();
  if (scheme && SCRIPT_SCHEMES.has(scheme)) {
    findings.push({ severity: "critical", title: `Link uses a ${scheme}: address`, detail: "It runs code or opens content directly instead of going to a website." });
    return findings;
  }
  if (scheme && !HARMLESS_SCHEMES.has(scheme)) {
    findings.push({ severity: "warning", title: `Link opens an app (${scheme}:)`, detail: "Not a web page. Some of these handlers have been used to run malware." });
    return findings;
  }
  const host = hostOf(squashed);
  if (!host) return findings;
  const claimed = text ? claimedHost(text) : null;
  if (claimed && hostKey(claimed) !== hostKey(host)) {
    findings.push({
      severity: "critical",
      title: "Link text shows a different site",
      detail: `It shows ${claimed} but goes to ${host}. Click-tracking services do this too, but it's the classic phishing trick.`,
    });
  }
  if (parseIp(host.replace(/^\[|\]$/g, ""))) findings.push({ severity: "warning", title: "Link goes to a bare IP address", detail: host });
  try {
    if (new URL(squashed).username) findings.push({ severity: "warning", title: "Link has text before @ in the address", detail: "Everything before the @ is ignored; it's there to look like another site." });
  } catch {
    // hostOf already parsed it
  }
  if (host.split(".").some((l) => l.startsWith("xn--"))) findings.push({ severity: "warning", title: "Link uses a punycode (xn--) domain", detail: "It may imitate another domain with look-alike characters." });
  return findings;
}

/** Every link in the message: HTML anchors with their text, and URLs written in plain-text bodies. De-duplicated. */
export function collectLinks(msg: Pick<ParsedMessage, "text">, html: readonly HtmlContent[]): TriageLink[] {
  const out: TriageLink[] = [];
  const seen = new Set<string>();
  const add = (link: Omit<TriageLink, "findings">) => {
    const key = `${link.href}\n${link.text ?? ""}`;
    if (seen.has(key) || out.length >= MAX_LINKS) return;
    seen.add(key);
    out.push({ ...link, findings: linkFindings(link.href, link.text) });
  };
  for (const h of html) for (const l of h.links) if (l.href && !l.href.startsWith("#")) add({ href: l.href, text: l.text, source: "html" });
  for (const t of msg.text) for (const i of extractIndicators(t)) if (i.kind === "url") add({ href: i.value, source: "text" });
  return out;
}

// --- Attachments ---

export interface AttachmentReport extends Omit<MimeAttachment, "bytes"> {
  /** What the first bytes say it is, if recognised. */
  sniffed: string | null;
  findings: Finding[];
}

const RISKY: { exts: string[]; severity: Finding["severity"]; title: string; detail: string }[] = [
  {
    exts: ["exe", "scr", "com", "pif", "bat", "cmd", "msi", "msix", "msp", "cpl", "dll", "jar", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "sct", "reg", "chm", "inf", "msc", "xll", "application", "appx", "appinstaller", "apk", "sh", "bin", "elf"],
    severity: "critical",
    title: "A program or script",
    detail: "Opening it runs code on the computer. Real invoices and documents never come as programs.",
  },
  {
    exts: ["lnk", "url", "website", "settingcontent-ms", "library-ms", "searchconnector-ms"],
    severity: "critical",
    title: "A Windows shortcut",
    detail: "Shortcuts can launch commands. They're a common way to deliver malware.",
  },
  {
    exts: ["iso", "img", "vhd", "vhdx"],
    severity: "critical",
    title: "A disk image",
    detail: "Disk images are used to slip programs past Windows' downloaded-file warnings.",
  },
  {
    exts: ["html", "htm", "shtml", "xhtml", "mht", "mhtml", "svg"],
    severity: "critical",
    title: "A web page",
    detail: "An attached web page often shows a fake sign-in form that sends your password to the attacker.",
  },
  {
    exts: ["docm", "dotm", "xlsm", "xltm", "xlam", "xlsb", "pptm", "potm", "ppam", "ppsm", "sldm"],
    severity: "critical",
    title: "An Office document with macros",
    detail: "Macros are programs. Never enable content in a document you didn't expect.",
  },
  {
    exts: ["one", "onepkg", "rtf"],
    severity: "warning",
    title: "A document type often abused",
    detail: "OneNote and RTF files have been used to deliver malware. Open only if you expected it.",
  },
  {
    exts: ["zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "cab", "ace", "arj", "lzh", "z"],
    severity: "warning",
    title: "An archive",
    detail: "Archives can hide programs from email filters, especially password-protected ones.",
  },
];

/** Extensions each recognised file signature can honestly have. */
const EXPECTED_EXT: Record<string, string[]> = {
  "Windows executable (PE)": ["exe", "dll", "scr", "com", "cpl", "sys", "ocx", "efi", "drv", "xll"],
  "Linux executable (ELF)": ["elf", "so", "bin", "out", "o"],
  "PDF document": ["pdf"],
  "ZIP archive (or Office document)": ["zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotx", "dotm", "xltx", "xltm", "xlam", "potx", "potm", "ppsx", "ppsm", "ppam", "sldx", "sldm", "xlsb", "vsdx", "odt", "ods", "odp", "odg", "epub", "jar", "apk", "xpi", "msix", "appx", "kmz", "xps", "oxps", "nupkg", "whl", "war", "ear", "aar", "ipa", "3mf", "onepkg"],
  "Legacy Office document (OLE)": ["doc", "dot", "xls", "xlt", "xla", "ppt", "pot", "pps", "msg", "msi", "msp", "vsd", "pub", "mpp", "one"],
  "gzip archive": ["gz", "tgz", "svgz"],
  "RAR archive": ["rar"],
  "7-Zip archive": ["7z"],
  "PNG image": ["png"],
  "JPEG image": ["jpg", "jpeg", "jpe", "jfif"],
  "GIF image": ["gif"],
  "RTF document": ["rtf"],
  "Java class / Mach-O": ["class", "dylib", "app", "macho"],
};
const EXECUTABLE_SIGNATURES = new Set(["Windows executable (PE)", "Linux executable (ELF)", "Java class / Mach-O"]);
/** Second-to-last extensions that make "invoice.pdf.exe" look like a document. */
const DECOY_EXTS = new Set(["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "csv", "rtf", "odt", "htm", "html", "mp3", "mp4", "wav"]);

const extOf = (name: string) => {
  const m = /\.([a-z0-9-]{1,20})$/i.exec(name.trim().replace(/[.\s]+$/, ""));
  return m ? m[1]!.toLowerCase() : "";
};

/** Risk notes for one attachment: risky type, a name that hides its type, and content that doesn't match the name. Pure. */
export function classifyAttachment(a: Pick<MimeAttachment, "filename" | "contentType" | "bytes">): { sniffed: string | null; findings: Finding[] } {
  const findings: Finding[] = [];
  const ext = extOf(a.filename);
  const sniffed = sniffFileType(a.bytes);

  const risky = RISKY.find((r) => r.exts.includes(ext));
  if (risky) findings.push({ severity: risky.severity, title: `${risky.title} (.${ext})`, detail: risky.detail });
  else if (!ext && a.contentType === "text/html") findings.push({ severity: "critical", title: RISKY[3]!.title, detail: RISKY[3]!.detail });

  const parts = a.filename.toLowerCase().split(".");
  if (risky && parts.length >= 3 && DECOY_EXTS.has(parts.at(-2)!)) {
    findings.push({ severity: "critical", title: "File name hides its real type", detail: `It looks like a .${parts.at(-2)} but is really a .${ext}.` });
  }
  if (/[‪-‮⁦-⁩]/.test(a.filename)) {
    findings.push({ severity: "critical", title: "File name contains hidden direction characters", detail: "They reverse part of the name so the real extension is disguised." });
  }

  if (sniffed) {
    const expected = EXPECTED_EXT[sniffed] ?? [];
    if (!expected.includes(ext)) {
      const exec = EXECUTABLE_SIGNATURES.has(sniffed);
      findings.push({
        severity: exec ? "critical" : "warning",
        title: ext ? `Content doesn't match the .${ext} name` : "File has no extension",
        detail: `The content is a ${sniffed}${exec ? ", which runs as a program" : ""}.`,
      });
    }
  }
  return { sniffed, findings: sortFindings(findings) };
}

export function reportAttachment(a: MimeAttachment): AttachmentReport {
  return { filename: a.filename, contentType: a.contentType, size: a.size, ...classifyAttachment(a) };
}

export async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** "512 B", "1.4 KB", "2.3 MB" */
export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

// --- Indicators ---

/** Most text scanned for indicators, so a huge body can't freeze a phone. */
export const MAX_SCAN_CHARS = 1_000_000;

/**
 * Every indicator in the message for the bulk view: from the bodies (plain text and visible HTML text), link
 * targets, the sender addresses and their domains, Received hop IPs, and attachment SHA-256s. De-duplicated.
 */
export function triageIndicators(msg: Pick<ParsedMessage, "text">, html: readonly HtmlContent[], links: readonly TriageLink[], headers: HeaderAnalysis | null, hashes: readonly string[]): Extracted[] {
  const lines: string[] = [];
  if (headers) {
    for (const m of [headers.from, headers.replyTo, headers.returnPath]) if (m) lines.push(m.address, m.domain);
    for (const h of headers.hops) if (h.ip) lines.push(h.ip);
  }
  lines.push(...links.filter((l) => hostOf(l.href)).map((l) => l.href), ...msg.text, ...html.map((h) => h.text), ...hashes);
  return extractIndicators(lines.join("\n").slice(0, MAX_SCAN_CHARS));
}

// --- Summary ---

/** The strongest red flags, in plain English: critical first, then warnings, at most `max`. Never says "safe". */
export function triageFlags(headers: HeaderAnalysis | null, links: readonly TriageLink[], attachments: readonly AttachmentReport[], max = 8): Finding[] {
  const out: Finding[] = [];
  if (headers) out.push(...headers.findings.filter((f) => f.severity !== "info"));

  // One line per kind of link problem, with the first example.
  const byTitle = new Map<string, { finding: Finding; count: number }>();
  for (const l of links)
    for (const f of l.findings) {
      const entry = byTitle.get(f.title);
      if (entry) entry.count++;
      else byTitle.set(f.title, { finding: f, count: 1 });
    }
  for (const { finding, count } of byTitle.values()) {
    out.push(count === 1 ? finding : { ...finding, title: `${finding.title} (${count} links)` });
  }

  for (const a of attachments) for (const f of a.findings) if (f.severity !== "info") out.push({ ...f, title: `${a.filename}: ${f.title}` });
  return sortFindings(out).slice(0, max);
}

export const NO_FLAGS = "No obvious red flags. That doesn't make it safe: if the message was unexpected, check with the sender another way.";

// --- Ticket note ---

export interface TicketInput {
  headers: HeaderAnalysis | null;
  flags: Finding[];
  attachments: readonly AttachmentReport[];
  /** SHA-256 per attachment, same order; missing while still being computed. */
  hashes: readonly (string | undefined)[];
  indicators: readonly Extracted[];
  /** Reputation results, as exports show them (no Safe Browsing). Only checked items. */
  verdicts: ExportVerdicts;
  now?: number;
}

const VERDICT_WORDS = { "not-listed": "not listed", incomplete: "not listed (some sources unavailable)" } as const;

/** A plain-text summary for a ticket or chat. Everything clickable is defanged. */
export function ticketNote(t: TicketInput): string {
  const h = t.headers;
  const mailbox = (m?: { display: string; address: string }) => (m ? `${m.display ? `"${defangText(m.display)}" ` : ""}<${defangEmail(m.address)}>` : "(none)");
  const lines = ["Reported email: phishing triage", `Subject: ${h?.subject ? defangText(h.subject) : "(none)"}`, `From: ${mailbox(h?.from)}`];
  if (h?.replyTo) lines.push(`Reply-To: ${mailbox(h.replyTo)}`);
  if (h?.date) lines.push(`Date: ${h.date}`);
  const auth = h?.auth ?? [];
  lines.push(`Authentication: ${auth.length === 0 ? "no results in the headers" : auth.map((r) => `${r.method.toUpperCase()} ${r.result}${r.domain ? ` (${defangHost(r.domain)})` : ""}`).join(", ")}`);

  lines.push("", "Red flags:", ...findingLines(t.flags, "None obvious. That doesn't make it safe."));

  lines.push("", `Attachments (${t.attachments.length}):`);
  if (t.attachments.length === 0) lines.push("- None");
  t.attachments.forEach((a, i) => {
    lines.push(`- ${defangText(a.filename)} (${a.contentType}, ${formatSize(a.size)}${a.sniffed ? `, content: ${a.sniffed}` : ""})`);
    lines.push(`    SHA-256: ${t.hashes[i] ?? "(not calculated)"}`);
  });

  lines.push("", `Indicators (${t.indicators.length}, defanged):`);
  if (t.indicators.length === 0) lines.push("- None");
  for (const i of t.indicators) {
    const v = t.verdicts.get(extractedKey(i));
    const verdict = !v ? "" : v.verdict === "listed" ? ` [listed by ${v.listedBy.join(", ")}]` : ` [${VERDICT_WORDS[v.verdict]}]`;
    lines.push(`- ${defangExtracted(i)}${verdict}`);
  }

  lines.push("", `Analysed ${formatUtc(t.now ?? Date.now())} in the browser, via bluebench.dev. Indicators defanged for safe sharing.`);
  if (t.verdicts.size > 0) lines.push("Reputation from URLhaus, ThreatFox and MalwareBazaar; \"not listed\" doesn't mean safe.");
  return lines.join("\n");
}

// --- Hand-off from the Lookup paste box ---

let pending: string | null = null;

/** Lookup hands a pasted message to the triage page. Kept in memory only: never in the URL or storage. */
export function handOffMessage(text: string) {
  pending = text;
}
export const peekHandOff = () => pending;
export function clearHandOff() {
  pending = null;
}
