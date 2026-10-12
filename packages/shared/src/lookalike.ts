import { normalizeDomain, orgDomain } from "./domain.ts";

/**
 * Lookalike domains: names someone could register to impersonate a domain (typos, homoglyphs,
 * other TLDs). The daily watcher resolves each one and flags those that have a website or mail.
 *
 * The list is deterministic (same input, same order), because the watcher scans it in chunks across
 * cron runs and resumes from a stored position.
 */

export type LookalikeKind = "homoglyph" | "tld" | "omission" | "transposition" | "repetition" | "hyphen" | "replacement";

export interface Lookalike {
  /** ASCII (punycode for internationalized names). */
  domain: string;
  kind: LookalikeKind;
}

/** Most variants checked per domain each day. Each costs one or two DNS queries in the cron's budget. */
export const MAX_LOOKALIKES = 120;

/** Characters that look alike in most fonts, in both directions where it makes sense. */
const ASCII_HOMOGLYPHS: readonly [string, string][] = [
  ["o", "0"], ["0", "o"], ["l", "1"], ["1", "l"], ["i", "1"], ["i", "l"], ["l", "i"],
  ["rn", "m"], ["m", "rn"], ["vv", "w"], ["w", "vv"], ["cl", "d"], ["d", "cl"], ["q", "g"], ["g", "q"],
];

/** Latin letters and the Cyrillic letters drawn the same way (registered as punycode IDNs). */
const IDN_HOMOGLYPHS: Readonly<Record<string, string>> = {
  a: "а", c: "с", e: "е", i: "і", o: "о", p: "р", x: "х", y: "у",
};

/** TLDs most often used for impersonation, tried in place of the domain's own suffix. */
const TLDS = ["com", "net", "org", "co", "io", "info", "app", "dev", "online", "site", "shop", "xyz"];

/** Neighbouring keys on a QWERTY keyboard (fat-finger typos). */
const ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"];
function neighbours(ch: string): string[] {
  const out: string[] = [];
  ROWS.forEach((row, r) => {
    const i = row.indexOf(ch);
    if (i < 0) return;
    for (const [dr, di] of [[0, -1], [0, 1], [-1, 0], [-1, 1], [1, -1], [1, 0]] as const) {
      const c = ROWS[r + dr]?.[i + di];
      if (c) out.push(c);
    }
  });
  return out;
}

/**
 * Lookalikes of a domain's registrable name (subdomains are ignored: anyone impersonating
 * mail.example.com registers a name like examp1e.com). Ordered most convincing first and capped.
 */
export function lookalikes(input: string, max = MAX_LOOKALIKES): Lookalike[] {
  const host = normalizeDomain(input);
  if (!host) return [];
  const org = orgDomain(host);
  const dot = org.indexOf(".");
  const name = org.slice(0, dot);
  const suffix = org.slice(dot + 1);

  const seen = new Set([org]);
  const out: Lookalike[] = [];
  const add = (label: string, kind: LookalikeKind, tld = suffix) => {
    if (out.length >= max) return;
    const domain = normalizeDomain(`${label}.${tld}`);
    if (!domain || label.startsWith("-") || label.endsWith("-") || seen.has(domain)) return;
    seen.add(domain);
    out.push({ domain, kind });
  };
  const splice = (i: number, len: number, insert: string) => name.slice(0, i) + insert + name.slice(i + len);

  // Punycode names: character tricks on the encoded form make no sense, so only other TLDs.
  const ascii = !name.startsWith("xn--");

  if (ascii) {
    for (const [from, to] of ASCII_HOMOGLYPHS) {
      for (let i = name.indexOf(from); i >= 0; i = name.indexOf(from, i + 1)) add(splice(i, from.length, to), "homoglyph");
    }
    for (let i = 0; i < name.length; i++) {
      const glyph = IDN_HOMOGLYPHS[name[i]!];
      if (glyph) add(splice(i, 1, glyph), "homoglyph");
    }
  }
  for (const tld of TLDS) if (tld !== suffix) add(name, "tld", tld);
  if (!ascii) return out;

  for (let i = 0; i < name.length; i++) if (name.length > 1) add(splice(i, 1, ""), "omission");
  for (let i = 0; i < name.length - 1; i++) {
    if (name[i] !== name[i + 1]) add(splice(i, 2, name[i + 1]! + name[i]!), "transposition");
  }
  for (let i = 0; i < name.length; i++) if (name[i] !== "-") add(splice(i, 0, name[i]!), "repetition");
  for (let i = 1; i < name.length; i++) if (name[i] !== "-" && name[i - 1] !== "-") add(splice(i, 0, "-"), "hyphen");
  for (let i = 0; i < name.length; i++) for (const n of neighbours(name[i]!)) add(splice(i, 1, n), "replacement");
  return out;
}
