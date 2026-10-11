import { orgDomain, type DomainCheck } from "@bluebench/shared";
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
      status: "fail",
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

export function parseDmarc(record: string): Map<string, string> {
  const tags = new Map<string, string>();
  for (const part of record.split(";")) {
    const [k, ...v] = part.split("=");
    if (k && v.length) tags.set(k.trim().toLowerCase(), v.join("=").trim());
  }
  return tags;
}

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
  const tags = parseDmarc(record);
  // A subdomain inheriting the org policy is governed by sp= if present.
  const policy = (at !== domain ? tags.get("sp") ?? tags.get("p") : tags.get("p"))?.toLowerCase();
  const pct = Number(tags.get("pct") ?? "100");
  const facts = [fact("Record", record), ...(at !== domain ? [fact("Inherited from", at)] : [])];
  if (!tags.has("rua")) facts.push(fact("Reports", "none requested (no rua=)"));

  if (policy !== "none" && policy !== "quarantine" && policy !== "reject") {
    return { status: "fail", summary: "The record has no valid p= policy, so receivers ignore it.", fix: "Set p=none, p=quarantine or p=reject.", facts };
  }
  if (policy === "none") {
    return {
      status: "warn",
      summary: "Policy is p=none: spoofed email is reported but still delivered.",
      fix: "Once reports show your real senders pass, change to p=quarantine, then p=reject.",
      facts,
    };
  }
  if (pct < 100) {
    return {
      status: "warn",
      summary: `Policy p=${policy} applies to only ${pct}% of failing mail.`,
      fix: "Raise pct to 100 (or remove it) once you're confident.",
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
 * plus generic defaults. Selectors can be any name, so "none found" is only a hint.
 */
export const DKIM_SELECTORS = [
  "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "default", "dkim", "mail",
  "fm1", "protonmail", "zoho", "sig1", "mandrill",
] as const;

/** Rough RSA key size from the base64 p= value; 0 for an empty (revoked) key. */
export function dkimKeyBits(p: string, keyType = "rsa"): number {
  const clean = p.replace(/\s+/g, "");
  if (!clean) return 0;
  if (keyType.toLowerCase() === "ed25519") return 256;
  const bytes = Math.floor((clean.replace(/=+$/, "").length * 3) / 4);
  if (bytes < 120) return 512;
  if (bytes < 200) return 1024;
  if (bytes < 350) return 2048;
  return 4096;
}

export async function dkimCheck(r: Resolver, domain: string, receivesMail: boolean): Promise<Check> {
  const found: { selector: string; bits: number }[] = [];
  let complete = true;
  await Promise.all(
    DKIM_SELECTORS.map(async (selector) => {
      try {
        const rec = (await r.txt(`${selector}._domainkey.${domain}`)).find((t) => /(^|;)\s*p=/i.test(t));
        if (!rec) return;
        const tags = parseDmarc(rec); // same tag=value; syntax
        found.push({ selector, bits: dkimKeyBits(tags.get("p") ?? "", tags.get("k")) });
      } catch {
        complete = false;
      }
    }),
  );
  found.sort((a, b) => DKIM_SELECTORS.indexOf(a.selector as never) - DKIM_SELECTORS.indexOf(b.selector as never));
  const live = found.filter((f) => f.bits > 0);
  const facts = found.map((f) => fact(`Selector ${f.selector}`, f.bits === 0 ? "revoked (empty key)" : f.bits === 256 ? "Ed25519 key" : `~${f.bits}-bit RSA key`));

  if (live.length === 0) {
    if (!receivesMail) return { status: "info", summary: "Not applicable: this domain doesn't receive email.", facts };
    if (!complete) return { status: "skipped", summary: "Couldn't finish probing for DKIM keys this time.", facts };
    return {
      status: "warn",
      summary: `No DKIM key at ${DKIM_SELECTORS.length} common selectors. Yours may use a custom name, so check with your mail provider.`,
      fix: "Turn on DKIM signing in your mail provider's settings and publish the key it gives you.",
      facts,
    };
  }
  const weak = live.filter((f) => f.bits < 2048 && f.bits !== 256);
  if (weak.length > 0) {
    return {
      status: "warn",
      summary: `Found DKIM key${live.length === 1 ? "" : "s"}, but ${weak.map((w) => w.selector).join(", ")} ${weak.length === 1 ? "is" : "are"} ${weak[0]!.bits}-bit, which is weak.`,
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
