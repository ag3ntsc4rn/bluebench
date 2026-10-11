import { orgDomain } from "@bluebench/shared";
import { formatDuration, formatUtc, sortFindings, type Finding } from "./findings";

export interface HeaderField {
  name: string;
  value: string;
}

/** Split raw headers into fields, unfolding continuation lines. Stops at the first blank line after a field. */
export function parseHeaderFields(raw: string): HeaderField[] {
  const fields: HeaderField[] = [];
  for (const line of raw.split(/\r?\n/)) {
    if (line.trim() === "") {
      if (fields.length) break;
      continue;
    }
    const last = fields.at(-1);
    if (/^[ \t]/.test(line)) {
      if (last) last.value += ` ${line.trim()}`;
      continue;
    }
    const m = /^([!-9;-~]+):\s*(.*)$/.exec(line);
    if (m) fields.push({ name: m[1]!, value: m[2]!.trim() });
  }
  return fields;
}

/** Decode RFC 2047 encoded words, e.g. =?UTF-8?B?...?= or =?iso-8859-1?Q?...?=. */
export function decodeEncodedWords(value: string): string {
  return value
    .replace(/(=\?[^?\s]+\?[BbQq]\?[^?\s]*\?=)\s+(?==\?)/g, "$1") // whitespace between encoded words is dropped
    .replace(/=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=/g, (whole, charset: string, enc: string, text: string) => {
      try {
        let bytes: Uint8Array;
        if (enc.toUpperCase() === "B") {
          const bin = atob(text);
          bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
        } else {
          const raw = text.replace(/_/g, " ").replace(/=([0-9a-f]{2})/gi, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
          bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0));
        }
        return new TextDecoder(charset.replace(/\*.*$/, "")).decode(bytes);
      } catch {
        return whole;
      }
    });
}

export interface Mailbox {
  display: string;
  address: string;
  domain: string;
}

export function parseMailbox(value: string): Mailbox | null {
  const decoded = decodeEncodedWords(value);
  const angle = /<\s*([^<>\s]+@[^<>\s]+)\s*>/.exec(decoded);
  const bare = angle ? null : /([^\s<>"(),;:]+@[^\s<>"(),;:]+)/.exec(decoded);
  const address = (angle?.[1] ?? bare?.[1])?.toLowerCase();
  if (!address) return null;
  const display = angle ? decoded.slice(0, angle.index).trim().replace(/^"(.*)"$/, "$1").trim() : "";
  return { display, address, domain: address.slice(address.lastIndexOf("@") + 1).replace(/[.>]+$/, "") };
}

/** Strip RFC 5322 comments (parenthesised, possibly nested). */
function stripComments(s: string): string {
  let out = "";
  let depth = 0;
  for (const ch of s) {
    if (ch === "(") depth++;
    else if (ch === ")" && depth > 0) depth--;
    else if (depth === 0) out += ch;
  }
  return out;
}

function parseDate(s: string): number | null {
  const ms = Date.parse(stripComments(s).replace(/\s+/g, " ").trim());
  return Number.isNaN(ms) ? null : ms;
}

export interface Hop {
  from?: string;
  by?: string;
  ip?: string;
  with?: string;
  /** Milliseconds since epoch, if the date parsed. */
  at?: number;
  atDisplay?: string;
  /** Seconds since the previous hop. */
  delay?: number;
  delayDisplay?: string;
}

export function parseReceived(value: string): Hop {
  const semi = value.lastIndexOf(";");
  const body = semi >= 0 ? value.slice(0, semi) : value;
  const at = semi >= 0 ? parseDate(value.slice(semi + 1)) : null;
  const ip =
    /\[(?:IPv6:)?([0-9a-f:.]+)\]/i.exec(body)?.[1] ??
    /\((?:[^()]*?\s)?((?:\d{1,3}\.){3}\d{1,3})\)/.exec(body)?.[1];
  const word = (key: string) => new RegExp(`(?:^|\\s)${key}\\s+([^\\s;()]+)`, "i").exec(stripComments(body))?.[1];
  return {
    from: word("from"),
    by: word("by"),
    with: word("with"),
    ip,
    ...(at !== null ? { at, atDisplay: formatUtc(at) } : {}),
  };
}

export type AuthMethod = "spf" | "dkim" | "dmarc";

export interface AuthResult {
  method: AuthMethod;
  /** Lowercase result keyword: pass, fail, softfail, neutral, none, temperror, permerror, policy… */
  result: string;
  /** Domain the result applies to: smtp.mailfrom / header.d / header.from. */
  domain?: string;
  selector?: string;
  /** Header it came from. */
  source: string;
}

/** Parse one Authentication-Results value (RFC 8601) into SPF/DKIM/DMARC results. */
export function parseAuthResults(value: string, source = "Authentication-Results"): AuthResult[] {
  const results: AuthResult[] = [];
  for (const segment of stripComments(value).split(";")) {
    const m = /^\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)/i.exec(segment);
    if (!m) continue;
    const props: Record<string, string> = {};
    for (const p of segment.matchAll(/([a-z]+\.[a-z-]+)\s*=\s*("[^"]*"|[^\s;]+)/gi)) {
      props[p[1]!.toLowerCase()] = p[2]!.replace(/^"|"$/g, "");
    }
    const method = m[1]!.toLowerCase() as AuthMethod;
    const domainOf = (v?: string) => v?.replace(/^.*@/, "").toLowerCase();
    const domain =
      method === "spf"
        ? domainOf(props["smtp.mailfrom"] ?? props["smtp.helo"])
        : method === "dkim"
          ? domainOf(props["header.d"] ?? props["header.i"])
          : domainOf(props["header.from"]);
    results.push({
      method,
      result: m[2]!.toLowerCase(),
      ...(domain ? { domain } : {}),
      ...(method === "dkim" && props["header.s"] ? { selector: props["header.s"] } : {}),
      source,
    });
  }
  return results;
}

export interface HeaderAnalysis {
  fields: HeaderField[];
  subject?: string;
  date?: string;
  messageId?: string;
  from?: Mailbox;
  replyTo?: Mailbox;
  returnPath?: Mailbox;
  /** Oldest first. */
  hops: Hop[];
  totalDelay?: string;
  auth: AuthResult[];
  dkimSignatures: { domain: string; selector?: string }[];
  findings: Finding[];
}

const AUTH_ORDER: AuthMethod[] = ["spf", "dkim", "dmarc"];

function tagValue(sig: string, tag: string): string | undefined {
  return new RegExp(`(?:^|;)\\s*${tag}\\s*=\\s*([^;\\s]+)`, "i").exec(sig)?.[1];
}

export function analyzeHeaders(raw: string): HeaderAnalysis {
  const fields = parseHeaderFields(raw);
  const all = (name: string) => fields.filter((f) => f.name.toLowerCase() === name).map((f) => f.value);
  const one = (name: string) => all(name)[0];
  const findings: Finding[] = [];

  const fromValues = all("from");
  const from = fromValues[0] ? parseMailbox(fromValues[0]) ?? undefined : undefined;
  const replyTo = one("reply-to") ? parseMailbox(one("reply-to")!) ?? undefined : undefined;
  const returnPath = one("return-path") ? parseMailbox(one("return-path")!) ?? undefined : undefined;

  // Received headers are prepended, so the top one is newest. Show oldest first.
  const hops = all("received").map(parseReceived).reverse();
  let backwards = false;
  for (let i = 1; i < hops.length; i++) {
    const prev = hops[i - 1]!.at;
    const cur = hops[i]!;
    if (prev === undefined || cur.at === undefined) continue;
    cur.delay = (cur.at - prev) / 1000;
    cur.delayDisplay = formatDuration(cur.delay);
    if (cur.delay < -60) backwards = true;
  }
  const dated = hops.filter((h) => h.at !== undefined);
  const totalDelay =
    dated.length >= 2 ? formatDuration((dated.at(-1)!.at! - dated[0]!.at!) / 1000) : undefined;

  // The topmost Authentication-Results was added by the receiving server: trust it most.
  let auth: AuthResult[] = [];
  const ar = one("authentication-results");
  if (ar) auth = parseAuthResults(ar);
  const arc = one("arc-authentication-results");
  if (arc) {
    for (const r of parseAuthResults(arc.replace(/^\s*i=\d+\s*;/, ""), "ARC-Authentication-Results")) {
      if (!auth.some((a) => a.method === r.method)) auth.push(r);
    }
  }
  const receivedSpf = one("received-spf");
  if (receivedSpf && !auth.some((a) => a.method === "spf")) {
    const result = /^\s*([a-z]+)/i.exec(receivedSpf)?.[1]?.toLowerCase();
    const domain = /envelope-from=[<"]*([^\s;<>"]+)/i.exec(receivedSpf)?.[1]?.replace(/^.*@/, "").toLowerCase();
    if (result) auth.push({ method: "spf", result, ...(domain ? { domain } : {}), source: "Received-SPF" });
  }
  auth.sort((a, b) => AUTH_ORDER.indexOf(a.method) - AUTH_ORDER.indexOf(b.method));

  const dkimSignatures = all("dkim-signature").flatMap((sig) => {
    const domain = tagValue(sig, "d")?.toLowerCase();
    const selector = tagValue(sig, "s");
    return domain ? [{ domain, ...(selector ? { selector } : {}) }] : [];
  });

  // --- Red flags ---
  const fromOrg = from && orgDomain(from.domain);
  const fromName = from?.domain ?? "the sender's domain";
  const best = (method: AuthMethod) => {
    const rs = auth.filter((a) => a.method === method);
    return rs.find((a) => a.result === "pass") ?? rs[0];
  };
  const spf = best("spf");
  const dkim = best("dkim");
  const dmarc = best("dmarc");

  if (fromValues.length > 1) {
    findings.push({ severity: "critical", title: "More than one From header", detail: "Mail clients may show a different sender than the one that was checked." });
  }
  if (!from) findings.push({ severity: "warning", title: "No sender address found", detail: "The From header is missing or unreadable." });

  if (auth.length === 0) {
    findings.push({
      severity: "info",
      title: "No authentication results",
      detail: "Copy the headers from the received message (e.g. \"Show original\") to see SPF, DKIM and DMARC.",
    });
  } else {
    if (!spf) findings.push({ severity: "warning", title: "SPF not checked" });
    else if (spf.result === "fail")
      findings.push({ severity: "critical", title: "SPF failed", detail: `The sending server isn't allowed to send mail for ${spf.domain ?? "this domain"}.` });
    else if (spf.result === "softfail")
      findings.push({ severity: "warning", title: "SPF soft fail", detail: `${spf.domain ?? "The domain"} says this server probably shouldn't send its mail.` });
    else if (spf.result !== "pass")
      findings.push({ severity: "warning", title: `SPF result: ${spf.result}`, detail: "The sending server couldn't be confirmed." });

    if (!dkim || dkim.result === "none")
      findings.push({ severity: "warning", title: "Not DKIM-signed", detail: "Nothing proves the message wasn't changed or forged." });
    else if (dkim.result !== "pass")
      findings.push({ severity: "critical", title: "DKIM signature didn't verify", detail: "The message may have been altered in transit, or forged." });
    else if (fromOrg && dkim.domain && orgDomain(dkim.domain) !== fromOrg && dmarc?.result !== "pass")
      findings.push({ severity: "info", title: "Signed by a different domain", detail: `DKIM signature is from ${dkim.domain}, not ${fromName}.` });

    if (!dmarc || dmarc.result === "none")
      findings.push({ severity: "warning", title: "No DMARC result", detail: `${fromName} may have no DMARC policy, so spoofing it is easier.` });
    else if (dmarc.result !== "pass")
      findings.push({ severity: "critical", title: "DMARC failed", detail: `This message doesn't prove it came from ${fromName}.` });
  }

  if (from && replyTo && orgDomain(replyTo.domain) !== fromOrg) {
    findings.push({ severity: "warning", title: "Replies go somewhere else", detail: `Reply-To is ${replyTo.address}, not ${fromName}.` });
  }
  if (from && returnPath && orgDomain(returnPath.domain) !== fromOrg && dmarc?.result !== "pass") {
    findings.push({
      severity: "info",
      title: "Bounce address on another domain",
      detail: `Return-Path is ${returnPath.domain}. Common with mailing services, but also seen in spoofing.`,
    });
  }
  if (from) {
    const shown = /[^\s<>"@]+@[^\s<>"@]+\.[a-z]{2,}/i.exec(from.display)?.[0]?.toLowerCase();
    if (shown && shown !== from.address) {
      findings.push({ severity: "critical", title: "Display name shows a different address", detail: `The name shows ${shown}, but the real sender is ${from.address}.` });
    }
  }
  if (backwards) {
    findings.push({ severity: "warning", title: "Hop times go backwards", detail: "A server clock is wrong, or a Received header was forged." });
  }
  if (!one("message-id")) findings.push({ severity: "info", title: "No Message-ID", detail: "Legitimate mail servers almost always add one." });

  return {
    fields,
    subject: one("subject") && decodeEncodedWords(one("subject")!),
    date: one("date"),
    messageId: one("message-id"),
    from,
    replyTo,
    returnPath,
    hops,
    totalDelay,
    auth,
    dkimSignatures,
    findings: sortFindings(findings),
  };
}
