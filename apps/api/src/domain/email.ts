import { base64ToBytes, orgDomain, parseIPv4, parseIPv6, type DomainCheck } from "@bluebench/shared";
import { BudgetExceeded, DNS_TYPES, type DnsAnswer, type Resolver } from "../dns.ts";

type Check = Omit<DomainCheck, "id">;
const fact = (label: string, value: string) => ({ label, value });

// ---------- MX ----------

export interface MxInfo {
  hosts: string[];
  /** RFC 7505 null MX ("0 ."): the domain explicitly accepts no mail. */
  nullMx: boolean;
  answer: DnsAnswer;
}

export async function getMx(r: Resolver, domain: string): Promise<MxInfo> {
  const answer = await r.query(domain, "MX");
  const mx = answer.records
    .filter((x) => x.type === DNS_TYPES.MX)
    .map((x) => {
      const [pref, host] = x.data.split(/\s+/);
      return { pref: Number(pref), host: (host ?? "").replace(/\.$/, "") };
    })
    .sort((a, b) => a.pref - b.pref);
  const nullMx = mx.length === 1 && mx[0]!.host === "";
  return { hosts: nullMx ? [] : mx.map((m) => m.host), nullMx, answer };
}

export function mxCheck(mx: MxInfo): Check {
  if (mx.nullMx) return { status: "info", summary: "Explicitly doesn't accept email (null MX).", facts: [] };
  if (mx.hosts.length === 0) {
    return { status: "info", summary: "No mail servers, so this domain doesn't receive email.", facts: [] };
  }
  return {
    status: "pass",
    summary: `Receives email via ${mx.hosts.length} mail server${mx.hosts.length === 1 ? "" : "s"}.`,
    facts: mx.hosts.slice(0, 5).map((h, i) => fact(i === 0 ? "Primary" : "Backup", h)),
  };
}

// ---------- SPF ----------

export interface SpfTerm {
  qualifier: "+" | "-" | "~" | "?";
  mechanism: string;
  value?: string;
}

/** Split an SPF record into terms. Modifiers (redirect=, exp=) come back with mechanism "redirect"/"exp". */
export function parseSpf(record: string): SpfTerm[] {
  return record
    .trim()
    .split(/\s+/)
    .slice(1) // "v=spf1"
    .filter(Boolean)
    .map((raw) => {
      const mod = /^(redirect|exp)=(.*)$/i.exec(raw);
      if (mod) return { qualifier: "+", mechanism: mod[1]!.toLowerCase(), value: mod[2] };
      const q = "+-~?".includes(raw[0]!) ? (raw[0] as SpfTerm["qualifier"]) : "+";
      const body = q === raw[0] ? raw.slice(1) : raw;
      const m = /^([a-z0-9]+)(?:[:/](.*))?$/i.exec(body);
      return { qualifier: q, mechanism: (m?.[1] ?? body).toLowerCase(), value: m?.[2] };
    });
}

const isSpf = (txt: string) => /^v=spf1(\s|$)/i.test(txt);

/** RFC 7208 domain-spec: macro-string (literals, %{x…} macros, %%, %_, %-), not empty. */
const DOMAIN_SPEC = /^(?:[\x21-\x24\x26-\x7e]|%\{[slodiphcrtv]\d*r?[.\-+,/_=]*\}|%[%_-])+$/i;
const CIDR4 = /^\d{1,2}$/;
const CIDR6 = /^\d{1,3}$/;

/** The part after "a" or "mx": optional ":domain-spec", then optional "/ip4-cidr" and "//ip6-cidr". */
function validDualCidr(spec: string): boolean {
  const m = /^(?::([^/]+))?(?:\/(\d{1,2}))?(?:\/\/(\d{1,3}))?$/.exec(spec);
  if (!m) return false;
  if (m[1] !== undefined && !DOMAIN_SPEC.test(m[1])) return false;
  return (m[2] === undefined || Number(m[2]) <= 32) && (m[3] === undefined || Number(m[3]) <= 128);
}

/**
 * Whole-record syntax check (RFC 7208 §4.6 and §12): any error makes receivers return permerror, so SPF
 * then protects nothing. Returns the first offending term, or null if the record is well formed.
 */
export function spfSyntaxError(record: string): string | null {
  const terms = record.trim().split(/\s+/).slice(1).filter(Boolean);
  const modifiers = new Set<string>();
  for (const raw of terms) {
    const mod = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(raw);
    if (mod) {
      const name = mod[1]!.toLowerCase();
      if ((name === "redirect" || name === "exp") && (modifiers.has(name) || !DOMAIN_SPEC.test(mod[2]!))) return raw;
      modifiers.add(name); // unknown modifiers are allowed and ignored
      continue;
    }
    const body = "+-~?".includes(raw[0]!) ? raw.slice(1) : raw;
    const m = /^([a-z0-9]+)(.*)$/i.exec(body);
    if (!m) return raw;
    const mech = m[1]!.toLowerCase();
    const rest = m[2]!; // "", ":arg", "/cidr" …
    const arg = rest.startsWith(":") ? rest.slice(1) : undefined;
    switch (mech) {
      case "all":
        if (rest) return raw;
        break;
      case "include":
      case "exists":
        if (!arg || !DOMAIN_SPEC.test(arg)) return raw;
        break;
      case "ptr":
        if (rest && (!arg || !DOMAIN_SPEC.test(arg))) return raw;
        break;
      case "a":
      case "mx":
        if (!validDualCidr(rest)) return raw;
        break;
      case "ip4": {
        const [ip, cidr, extra] = (arg ?? "").split("/");
        if (!ip || parseIPv4(ip) === null || extra !== undefined || (cidr !== undefined && (!CIDR4.test(cidr) || Number(cidr) > 32))) return raw;
        break;
      }
      case "ip6": {
        const slash = (arg ?? "").lastIndexOf("/");
        const ip = slash < 0 ? arg : arg!.slice(0, slash);
        const cidr = slash < 0 ? undefined : arg!.slice(slash + 1);
        if (!ip || parseIPv6(ip) === null || (cidr !== undefined && (!CIDR6.test(cidr) || Number(cidr) > 128))) return raw;
        break;
      }
      default:
        return raw; // unknown mechanism
    }
  }
  return null;
}

/** True when the domain's SPF says it sends no email at all: exactly "v=spf1 -all". */
export function spfSendsNoMail(records: readonly string[]): boolean {
  const spf = records.filter(isSpf);
  return spf.length === 1 && /^v=spf1\s+-all$/i.test(spf[0]!.trim());
}
/** Mechanisms and modifiers that cost a DNS lookup (RFC 7208 §4.6.4). */
const LOOKUP_TERMS = new Set(["include", "a", "mx", "ptr", "exists", "redirect"]);
const SPF_LOOKUP_LIMIT = 10;

/** Count DNS-querying terms recursively through include: and redirect=, stopping once over the limit. */
async function countSpfLookups(r: Resolver, terms: SpfTerm[], seen: Set<string>): Promise<{ count: number; complete: boolean }> {
  let count = 0;
  let complete = true;
  for (const t of terms) {
    if (!LOOKUP_TERMS.has(t.mechanism)) continue;
    count++;
    if (count > SPF_LOOKUP_LIMIT) return { count, complete };
    if ((t.mechanism === "include" || t.mechanism === "redirect") && t.value && !seen.has(t.value.toLowerCase())) {
      seen.add(t.value.toLowerCase());
      try {
        const child = (await r.txt(t.value)).find(isSpf);
        if (!child) continue;
        const sub = await countSpfLookups(r, parseSpf(child), seen);
        count += sub.count;
        complete &&= sub.complete;
        if (count > SPF_LOOKUP_LIMIT) return { count, complete };
      } catch (e) {
        if (e instanceof BudgetExceeded) return { count, complete: false };
        throw e;
      }
    }
  }
  return { count, complete };
}

export async function spfCheck(r: Resolver, domain: string, receivesMail: boolean): Promise<Check> {
  const records = (await r.txt(domain)).filter(isSpf);
  const fixNoMail = `Add a TXT record at ${domain}: v=spf1 -all (this domain sends no email).`;
  if (records.length === 0) {
    return {
      // A domain without mail servers is lower risk (DMARC may still protect it), but should say it sends nothing.
      status: receivesMail ? "fail" : "warn",
      summary: "No SPF record, so anyone can send email claiming to be from this domain.",
      fix: receivesMail
        ? `Add a TXT record at ${domain} listing your mail senders, e.g. v=spf1 include:<your provider> -all.`
        : fixNoMail,
      facts: [],
    };
  }
  if (records.length > 1) {
    return {
      status: "fail",
      summary: `${records.length} SPF records. Receivers treat that as an error and ignore all of them.`,
      fix: "Merge them into a single v=spf1 TXT record.",
      facts: records.map((rec, i) => fact(`Record ${i + 1}`, rec)),
    };
  }
  const record = records[0]!;
  const syntax = spfSyntaxError(record);
  if (syntax) {
    return {
      status: "fail",
      summary: `The record has a syntax error ("${syntax}"), so receivers treat it as an error (permerror) and SPF protects nothing.`,
      fix: "Correct or remove that term. Each needs a valid form, e.g. ip4:192.0.2.0/24, include:_spf.example.com or -all.",
      facts: [fact("Record", record)],
    };
  }
  const terms = parseSpf(record);
  const all = terms.find((t) => t.mechanism === "all");
  const redirect = terms.find((t) => t.mechanism === "redirect");
  const { count, complete } = await countSpfLookups(r, terms, new Set([domain]));
  const facts = [fact("Record", record), fact("DNS lookups", complete ? `${count} of ${SPF_LOOKUP_LIMIT}` : `at least ${count}`)];

  if (count > SPF_LOOKUP_LIMIT) {
    return {
      status: "fail",
      summary: `Needs more than ${SPF_LOOKUP_LIMIT} DNS lookups, so receivers stop evaluating it (permerror).`,
      fix: "Remove unused include: entries, or replace some with the ip4:/ip6: ranges they cover.",
      facts,
    };
  }
  if (all?.qualifier === "+") {
    return { status: "fail", summary: "Ends in +all, which allows every server on the internet to send as you.", fix: "Change +all to -all (or ~all).", facts };
  }
  if (terms.some((t) => t.mechanism === "ptr")) {
    return { status: "warn", summary: "Uses ptr, which is slow, unreliable and deprecated.", fix: "Replace ptr with ip4:/ip6: or include: terms.", facts };
  }
  if (!all && !redirect) {
    return {
      status: "warn",
      summary: "Doesn't end with an all rule, so mail from unlisted servers isn't rejected.",
      fix: "End the record with -all (or ~all while you're testing).",
      facts,
    };
  }
  if (all?.qualifier === "?") {
    return { status: "warn", summary: "Ends in ?all, which tells receivers nothing about unlisted senders.", fix: "Change ?all to -all (or ~all).", facts };
  }
  const how = all?.qualifier === "-" ? "Unlisted senders fail (-all)." : all ? "Unlisted senders soft-fail (~all); DMARC enforcement does the rest." : "Delegated with redirect=.";
  return { status: "pass", summary: `One valid record. ${how}`, facts };
}

// ---------- DMARC ----------

/**
 * DKIM-style tag list ("v=DMARC1; p=reject"), shared by DMARC and DKIM records. A repeated tag makes the
 * whole list invalid (RFC 6376 §3.2), so duplicates are reported instead of silently overwriting.
 */
export function parseTagList(record: string): { tags: Map<string, string>; duplicates: string[] } {
  const tags = new Map<string, string>();
  const duplicates: string[] = [];
  for (const part of record.split(";")) {
    const [k, ...v] = part.split("=");
    const key = k?.trim().toLowerCase();
    if (!key || !v.length) continue;
    if (tags.has(key)) duplicates.push(key);
    else tags.set(key, v.join("=").trim());
  }
  return { tags, duplicates };
}

export const parseDmarc = (record: string): Map<string, string> => parseTagList(record).tags;

/** One step down, as RFC 9989 asks receivers to apply under testing mode (t=y). */
const ONE_LOWER: Record<string, string> = { reject: "quarantine", quarantine: "none" };

const isDmarc = (txt: string) => /^v=DMARC1\s*(;|$)/i.test(txt);

export async function dmarcCheck(r: Resolver, domain: string, receivesMail: boolean): Promise<Check> {
  let at = domain;
  let records = (await r.txt(`_dmarc.${domain}`)).filter(isDmarc);
  const org = orgDomain(domain);
  if (records.length === 0 && org !== domain) {
    at = org; // receivers fall back to the organizational domain's policy
    records = (await r.txt(`_dmarc.${org}`)).filter(isDmarc);
  }
  const startFix = receivesMail
    ? `Add a TXT record at _dmarc.${domain}: v=DMARC1; p=none; rua=mailto:dmarc@${domain}. Watch the reports, then move to p=quarantine and p=reject.`
    : `Add a TXT record at _dmarc.${domain}: v=DMARC1; p=reject (this domain sends no email).`;
  if (records.length === 0) {
    return { status: "fail", summary: "No DMARC record, so spoofed email from this domain isn't blocked or reported.", fix: startFix, facts: [] };
  }
  if (records.length > 1) {
    return { status: "fail", summary: "More than one DMARC record, so receivers ignore them all.", fix: "Keep a single v=DMARC1 record.", facts: [] };
  }
  const record = records[0]!;
  const { tags, duplicates } = parseTagList(record);
  // A subdomain inheriting the org policy is governed by sp= if present.
  const policy = (at !== domain ? tags.get("sp") ?? tags.get("p") : tags.get("p"))?.toLowerCase();
  const facts = [fact("Record", record), ...(at !== domain ? [fact("Inherited from", at)] : [])];
  if (!tags.has("rua")) facts.push(fact("Reports", "none requested (no rua=)"));

  if (duplicates.length > 0) {
    return {
      status: "fail",
      summary: `The record repeats the ${[...new Set(duplicates)].map((d) => `${d}=`).join(", ")} tag, which makes it invalid, so receivers can't rely on it.`,
      fix: "Keep each tag once, e.g. v=DMARC1; p=reject; rua=mailto:…",
      facts,
    };
  }
  if (policy !== "none" && policy !== "quarantine" && policy !== "reject") {
    return { status: "fail", summary: "The record has no valid p= policy, so receivers ignore it.", fix: "Set p=none, p=quarantine or p=reject.", facts };
  }
  // RFC 9989 testing mode: receivers apply one level below the stated policy.
  if (tags.get("t")?.toLowerCase() === "y" && policy !== "none") {
    return {
      status: "warn",
      summary: `Policy p=${policy} is in testing mode (t=y), so receivers apply p=${ONE_LOWER[policy]} instead.`,
      fix: "Once reports show your real senders pass, remove t=y to apply the policy in full.",
      facts,
    };
  }
  if (policy === "none") {
    return {
      status: "warn",
      summary: "Policy is p=none: spoofed email is reported but still delivered.",
      fix: "Once reports show your real senders pass, change to p=quarantine, then p=reject.",
      facts,
    };
  }
  // pct was removed by RFC 9989 (replaced by t=); older receivers still apply it, current ones ignore it.
  const pct = tags.has("pct") ? Number(tags.get("pct")) : 100;
  if (!(pct >= 100)) {
    return {
      status: "warn",
      summary: `Uses pct=${tags.get("pct")}, which the current DMARC standard (RFC 9989) removed: older receivers apply p=${policy} to only that share of failing mail, newer ones ignore it.`,
      fix: "Remove pct. To test a stricter policy, use t=y instead.",
      facts,
    };
  }
  return {
    status: "pass",
    summary: policy === "reject" ? "Spoofed email is rejected (p=reject)." : "Spoofed email goes to spam (p=quarantine).",
    facts,
  };
}

// ---------- DKIM ----------

/**
 * Common selectors: Google, Microsoft 365, Mailchimp/Mandrill, Fastmail, Proton, Zoho, iCloud,
 * Resend, Mailjet, Mailgun and HubSpot, plus generic defaults. Each costs one DNS query of the report's budget. Selectors can be any name, so "none found" is only a hint.
 */
export const DKIM_SELECTORS = [
  "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "default", "dkim", "mail",
  "fm1", "protonmail", "zoho", "sig1", "mandrill", "resend", "mailjet", "smtp", "hs1",
] as const;

/** Read one DER element (tag, contents) at `at`. Null if it runs past the buffer. */
function der(b: Uint8Array, at: number): { tag: number; start: number; end: number } | null {
  if (at + 2 > b.length) return null;
  const tag = b[at]!;
  let len = b[at + 1]!;
  let start = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 3 || start + n > b.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | b[start + i]!;
    start += n;
  }
  return start + len <= b.length ? { tag, start, end: start + len } : null;
}

const RSA_OID = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]; // 1.2.840.113549.1.1.1

/** Modulus size of a DER RSAPublicKey (SEQUENCE { INTEGER n, INTEGER e }), or null if malformed. */
function rsaPublicKeyBits(b: Uint8Array, at = 0): number | null {
  const seq = der(b, at);
  if (!seq || seq.tag !== 0x30) return null;
  const n = der(b, seq.start);
  const e = n && der(b, n.end);
  if (!n || n.tag !== 0x02 || !e || e.tag !== 0x02 || e.end !== seq.end) return null;
  let i = n.start;
  while (i < n.end && b[i] === 0) i++; // leading zero bytes keep the integer positive
  if (i === n.end) return null;
  return (n.end - i) * 8 - Math.clz32(b[i]!) + 24;
}

export type DkimKey = { kind: "revoked" } | { kind: "invalid"; why: string } | { kind: "rsa"; bits: number } | { kind: "ed25519" };

/**
 * Decode a DKIM p= value for its k= type (RFC 6376, RFC 8463). RSA keys may be SubjectPublicKeyInfo
 * (what most providers publish) or a bare RSAPublicKey; the size comes from the parsed modulus.
 */
export function parseDkimKey(p: string, keyType = "rsa"): DkimKey {
  const clean = p.replace(/\s+/g, "");
  if (!clean) return { kind: "revoked" };
  const bytes = /^[A-Za-z0-9+/]+={0,2}$/.test(clean) ? base64ToBytes(clean) : null;
  if (!bytes) return { kind: "invalid", why: "the key isn't valid base64" };
  const k = keyType.toLowerCase();
  if (k === "ed25519") return bytes.length === 32 ? { kind: "ed25519" } : { kind: "invalid", why: "an Ed25519 key must be 32 bytes" };
  if (k !== "rsa") return { kind: "invalid", why: `unknown key type k=${keyType}` };

  const top = der(bytes, 0);
  if (!top || top.tag !== 0x30 || top.end !== bytes.length) return { kind: "invalid", why: "the key isn't a valid RSA public key" };
  const first = der(bytes, top.start);
  if (first?.tag === 0x02) {
    const bits = rsaPublicKeyBits(bytes);
    return bits ? { kind: "rsa", bits } : { kind: "invalid", why: "the key isn't a valid RSA public key" };
  }
  // SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { OID rsaEncryption, … }, BIT STRING { 0, RSAPublicKey } }
  const oid = first?.tag === 0x30 ? der(bytes, first.start) : null;
  const isRsa = oid?.tag === 0x06 && oid.end - oid.start === RSA_OID.length && RSA_OID.every((x, i) => bytes[oid.start + i] === x);
  const bitString = first && der(bytes, first.end);
  if (!isRsa || !bitString || bitString.tag !== 0x03 || bytes[bitString.start] !== 0) return { kind: "invalid", why: "the key isn't a valid RSA public key" };
  const bits = rsaPublicKeyBits(bytes, bitString.start + 1);
  return bits ? { kind: "rsa", bits } : { kind: "invalid", why: "the key isn't a valid RSA public key" };
}

/**
 * `sendsNoMail`: SPF says the domain sends nothing (v=spf1 -all). Only then is a missing key "not
 * applicable": no MX says nothing about sending, since MX is for receiving.
 */
export async function dkimCheck(r: Resolver, domain: string, sendsNoMail: boolean): Promise<Check> {
  const found: { selector: string; key: DkimKey }[] = [];
  let complete = true;
  await Promise.all(
    DKIM_SELECTORS.map(async (selector) => {
      try {
        const rec = (await r.txt(`${selector}._domainkey.${domain}`)).find((t) => /(^|;)\s*p=/i.test(t));
        if (!rec) return;
        const { tags, duplicates } = parseTagList(rec);
        const key: DkimKey = duplicates.length > 0 ? { kind: "invalid", why: `the record repeats ${duplicates[0]}=` } : parseDkimKey(tags.get("p") ?? "", tags.get("k"));
        found.push({ selector, key });
      } catch {
        complete = false;
      }
    }),
  );
  found.sort((a, b) => DKIM_SELECTORS.indexOf(a.selector as never) - DKIM_SELECTORS.indexOf(b.selector as never));
  const describeKey = (k: DkimKey) =>
    k.kind === "revoked" ? "revoked (empty key)" : k.kind === "invalid" ? `invalid: ${k.why}` : k.kind === "ed25519" ? "Ed25519 key" : `${k.bits}-bit RSA key`;
  const facts = found.map((f) => fact(`Selector ${f.selector}`, describeKey(f.key)));
  const live = found.filter((f) => f.key.kind === "rsa" || f.key.kind === "ed25519");
  const invalid = found.filter((f) => f.key.kind === "invalid");
  const fixInvalid = "Republish the key exactly as your mail provider gives it (one TXT record, nothing added or cut off).";

  if (live.length === 0) {
    if (invalid.length > 0) {
      return {
        status: "fail",
        summary: `The DKIM key at ${invalid.map((f) => f.selector).join(", ")} is unusable (${(invalid[0]!.key as { why: string }).why}), so signatures can't be verified.`,
        fix: fixInvalid,
        facts,
      };
    }
    if (sendsNoMail) return { status: "info", summary: "Not applicable: SPF says this domain sends no email (v=spf1 -all).", facts };
    if (!complete) return { status: "skipped", summary: "Couldn't finish probing for DKIM keys this time.", facts };
    return {
      status: "warn",
      summary: `No DKIM key at ${DKIM_SELECTORS.length} common selectors. Yours may use a custom name, so check with your mail provider.`,
      fix: "Turn on DKIM signing in your mail provider's settings and publish the key it gives you.",
      facts,
    };
  }
  if (invalid.length > 0) {
    return {
      status: "warn",
      summary: `Found a usable DKIM key, but ${invalid.map((f) => f.selector).join(", ")} ${invalid.length === 1 ? "is" : "are"} unusable (${(invalid[0]!.key as { why: string }).why}).`,
      fix: fixInvalid,
      facts,
    };
  }
  const weak = live.filter((f) => f.key.kind === "rsa" && f.key.bits < 2048);
  if (weak.length > 0) {
    const bits = (weak[0]!.key as { bits: number }).bits;
    return {
      status: "warn",
      summary: `Found DKIM key${live.length === 1 ? "" : "s"}, but ${weak.map((w) => w.selector).join(", ")} ${weak.length === 1 ? "is" : "are"} ${bits}-bit, which is weak.`,
      fix: "Rotate to a 2048-bit key in your mail provider's DKIM settings.",
      facts,
    };
  }
  return { status: "pass", summary: `Found ${live.length} DKIM key${live.length === 1 ? "" : "s"} of good strength.`, facts };
}

// ---------- DNSSEC ----------

/** Judged from an answer we already have: SERVFAIL means broken signatures, AD means validated. */
export function dnssecCheck(answer: DnsAnswer): Check {
  if (answer.status === 2) {
    return {
      status: "fail",
      summary: "DNSSEC validation fails, so validating resolvers can't look this domain up at all.",
      fix: "Check the DS record at your registrar matches your DNS host's current key, or remove it.",
      facts: [],
    };
  }
  if (answer.ad) return { status: "pass", summary: "Signed, and the signatures validate.", facts: [] };
  return {
    status: "warn",
    summary: "Not signed, so DNS answers for this domain could be forged in transit.",
    fix: "Turn on DNSSEC at your DNS host and add the DS record it gives you at your registrar (on Cloudflare it's one click).",
    facts: [],
  };
}
