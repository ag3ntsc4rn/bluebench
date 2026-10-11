import { describe, expect, it } from "vitest";
import { covers, judgeCerts, toCertEntries } from "../src/domain/cert.ts";
import { dkimKeyBits, parseDmarc, parseSpf } from "../src/domain/email.ts";
import { parseHsts } from "../src/domain/web.ts";
import { joinTxt } from "../src/dns.ts";

const DAY = 86_400_000;
const NOW = Date.parse("2026-10-11T12:00:00Z");
const iso = (d: number) => new Date(NOW + d * DAY).toISOString().slice(0, 19);

describe("joinTxt", () => {
  it("joins multi-string TXT data and unescapes quotes", () => {
    expect(joinTxt('"v=spf1 include:a.test " "-all"')).toBe("v=spf1 include:a.test -all");
    expect(joinTxt('"say \\"hi\\""')).toBe('say "hi"');
  });
});

describe("parseSpf", () => {
  it("parses qualifiers, mechanisms and modifiers", () => {
    expect(parseSpf("v=spf1 ip4:192.0.2.0/24 include:_spf.google.com ~all")).toEqual([
      { qualifier: "+", mechanism: "ip4", value: "192.0.2.0/24" },
      { qualifier: "+", mechanism: "include", value: "_spf.google.com" },
      { qualifier: "~", mechanism: "all", value: undefined },
    ]);
    expect(parseSpf("v=spf1 redirect=_spf.example.com")).toEqual([{ qualifier: "+", mechanism: "redirect", value: "_spf.example.com" }]);
    expect(parseSpf("v=spf1 -a mx -all")[0]).toEqual({ qualifier: "-", mechanism: "a", value: undefined });
  });
});

describe("parseDmarc", () => {
  it("reads tags case-insensitively", () => {
    const t = parseDmarc("v=DMARC1; P=quarantine; pct=50; rua=mailto:a@example.com");
    expect(t.get("p")).toBe("quarantine");
    expect(t.get("pct")).toBe("50");
    expect(t.get("rua")).toBe("mailto:a@example.com");
  });
});

describe("dkimKeyBits", () => {
  it.each([
    [216, 1024],
    [392, 2048],
    [736, 4096],
  ])("base64 length %i ≈ %i-bit RSA", (len, bits) => {
    expect(dkimKeyBits("A".repeat(len))).toBe(bits);
  });
  it("reports revoked and Ed25519 keys", () => {
    expect(dkimKeyBits("")).toBe(0);
    expect(dkimKeyBits("A".repeat(44), "ed25519")).toBe(256);
  });
});

describe("parseHsts", () => {
  it("reads max-age and flags", () => {
    expect(parseHsts("max-age=31536000; includeSubDomains; preload")).toEqual({ maxAge: 31536000, includeSubDomains: true, preload: true });
    expect(parseHsts('max-age="600"')).toEqual({ maxAge: 600, includeSubDomains: false, preload: false });
  });
});

describe("certificates", () => {
  it("matches exact names and one-level wildcards only", () => {
    expect(covers("example.com\nwww.example.com", "www.example.com")).toBe(true);
    expect(covers("*.example.com", "www.example.com")).toBe(true);
    expect(covers("*.example.com", "a.b.example.com")).toBe(false);
    expect(covers("notexample.com", "example.com")).toBe(false);
  });

  it("keeps only issuer and dates for covering certificates (no hostnames are cached)", () => {
    const rows = [
      { issuer_name: "C=US, O=Let's Encrypt, CN=R11", name_value: "example.com", not_before: iso(-1), not_after: iso(60) },
      { issuer_name: "C=US, O=Other, CN=X", name_value: "unrelated.test", not_before: iso(-1), not_after: iso(60) },
    ];
    expect(toCertEntries(rows, "example.com")).toEqual([{ issuer: "Let's Encrypt", notBefore: iso(-1), notAfter: iso(60) }]);
  });

  it("judges the newest unexpired certificate", () => {
    const e = (from: number, to: number) => ({ issuer: "Let's Encrypt", notBefore: iso(from), notAfter: iso(to) });
    expect(judgeCerts([e(-80, 10), e(-5, 40)], NOW)).toMatchObject({ status: "pass", summary: expect.stringContaining("in 40 days") });
    expect(judgeCerts([e(-30, 10)], NOW).status).toBe("warn"); // 10 days: renewal should have happened
    expect(judgeCerts([e(-30, 3)], NOW).status).toBe("fail");
    expect(judgeCerts([e(-90, -1)], NOW).status).toBe("warn"); // only expired ones: none current
  });
});
