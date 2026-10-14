import { describe, expect, it } from "vitest";
import { lookalikes, MAX_LOOKALIKES } from "./lookalike.ts";
import { normalizeDomain } from "./domain.ts";

const names = (d: string, max?: number) => lookalikes(d, max).map((l) => l.domain);

describe("lookalikes", () => {
  it("covers the usual impersonation tricks", () => {
    const all = names("paypal.com");
    expect(all).toEqual(
      expect.arrayContaining([
        "paypa1.com", // homoglyph
        "paypal.net", // other TLD
        "paypl.com", // omission
        "papyal.com", // transposition
        "payypal.com", // repetition
        "pay-pal.com", // hyphen
        "paypak.com", // neighbouring key
        normalizeDomain("pаypal.com"), // Cyrillic а, as punycode
      ]),
    );
  });

  it("finds multi-character homoglyphs", () => {
    expect(names("modern.com")).toEqual(expect.arrayContaining(["rnodern.com", "modem.com"]));
    expect(names("wired.com")).toContain("vvired.com");
  });

  it("works on the registrable name and keeps multi-label suffixes", () => {
    const all = names("mail.example.co.uk");
    expect(all).toContain("examp1e.co.uk");
    expect(all).toContain("example.com");
    expect(all.every((d) => !d.startsWith("mail."))).toBe(true);
  });

  it("never includes the domain itself, duplicates or invalid names", () => {
    const all = names("a-b.com", 1000);
    expect(all).not.toContain("a-b.com");
    expect(new Set(all).size).toBe(all.length);
    for (const d of all) expect(normalizeDomain(d)).toBe(d);
    expect(all.some((d) => /(^|\.)-|-\./.test(d))).toBe(false);
  });

  it("is deterministic and capped", () => {
    const long = "averyveryverylongcompanyname.com";
    expect(names(long)).toEqual(names(long));
    expect(names(long)).toHaveLength(MAX_LOOKALIKES);
  });

  it("puts the most convincing kinds first", () => {
    const kinds = lookalikes("google.com").map((l) => l.kind);
    expect(kinds.indexOf("homoglyph")).toBe(0);
    expect(kinds.indexOf("tld")).toBeLessThan(kinds.indexOf("omission"));
    expect(kinds.lastIndexOf("homoglyph")).toBeLessThan(kinds.indexOf("replacement"));
  });

  it("only swaps the TLD of an internationalized name", () => {
    const all = lookalikes("bücher.de");
    expect(all.length).toBeGreaterThan(0);
    expect(all.every((l) => l.kind === "tld" && l.domain.startsWith("xn--bcher-kva."))).toBe(true);
  });

  it("returns nothing for something that isn't a domain", () => {
    expect(lookalikes("not a domain")).toEqual([]);
  });

  it("mutates a hosting tenant's own name, not the platform's (#30)", () => {
    const all = names("victim.github.io");
    expect(all).toContain("v1ctim.github.io");
    expect(all.some((d) => d.startsWith("gith"))).toBe(false);
  });
});
