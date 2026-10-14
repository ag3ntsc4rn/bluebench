import { describe, expect, it } from "vitest";
import { covers, judgeCerts, toCertEntries } from "../src/domain/cert.ts";
import { dmarcTreeWalk, parseDkimKey, parseDmarc, parseSpf, parseTagList, spfSendsNoMail, spfSyntaxError } from "../src/domain/email.ts";
import { parseHsts } from "../src/domain/web.ts";
import { ED25519_RAW, RSA1024_SPKI, RSA2048_PKCS1, RSA2048_SPKI } from "./keys.ts";
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

describe("dmarcTreeWalk (RFC 9989 §4.10, #30)", () => {
  it("walks from the domain up to, but not including, the TLD", () => {
    expect(dmarcTreeWalk("a.b.c.example.com")).toEqual(["a.b.c.example.com", "b.c.example.com", "c.example.com", "example.com"]);
    expect(dmarcTreeWalk("victim.github.io")).toEqual(["victim.github.io", "github.io"]);
    expect(dmarcTreeWalk("example.com")).toEqual(["example.com"]);
  });

  it("jumps a very deep name to its last seven labels after the first query", () => {
    const deep = "l1.l2.l3.l4.l5.l6.l7.l8.l9.example.com"; // 11 labels
    const walk = dmarcTreeWalk(deep);
    expect(walk[0]).toBe(deep);
    expect(walk[1]).toBe("l5.l6.l7.l8.l9.example.com");
    expect(walk.at(-1)).toBe("example.com");
  });
});

describe("parseTagList", () => {
  it("reports repeated tags instead of letting the last one win (#33)", () => {
    expect(parseTagList("v=DMARC1; p=none; p=reject").duplicates).toEqual(["p"]);
    expect(parseTagList("v=DMARC1; p=none; p=reject").tags.get("p")).toBe("none");
    expect(parseTagList("v=DMARC1; p=reject; rua=mailto:a@b.example").duplicates).toEqual([]);
  });
});

describe("spfSyntaxError (#34)", () => {
  it.each([
    "v=spf1 ip4:not-an-ip -all",
    "v=spf1 ip4:999.999.999.999 -all",
    "v=spf1 include: -all",
    "v=spf1 definitely-not-a-mechanism -all",
    "v=spf1 ip4:192.0.2.0/33 -all",
    "v=spf1 ip6:2001:db8::/129 -all",
    "v=spf1 all:x",
    "v=spf1 redirect=a.example redirect=b.example",
    "v=spf1 a:/24 -all",
  ])("rejects %s", (record) => {
    expect(spfSyntaxError(record)).not.toBeNull();
  });

  it.each([
    "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 include:_spf.google.com -all",
    "v=spf1 a mx a:mail.example.com/24 mx//64 -all",
    "v=spf1 -a/24//64 ~all",
    "v=spf1 exists:%{i}._spf.example.com -all",
    "v=spf1 include:%{d}.spf.example.net ?all",
    "v=spf1 ptr -all",
    "v=spf1 redirect=_spf.example.com",
    "v=spf1 exp=explain._spf.%{d} unknown-mod=whatever -all",
    "v=spf1 -all",
  ])("accepts %s", (record) => {
    expect(spfSyntaxError(record)).toBeNull();
  });
});

describe("spfSendsNoMail (#31)", () => {
  it("is true only for an explicit v=spf1 -all", () => {
    expect(spfSendsNoMail(["v=spf1 -all"])).toBe(true);
    expect(spfSendsNoMail(["other", "v=spf1  -all "])).toBe(true);
    expect(spfSendsNoMail(["v=spf1 include:_spf.example.com -all"])).toBe(false);
    expect(spfSendsNoMail([])).toBe(false);
  });
});

describe("parseDkimKey (#38)", () => {
  it("reads the real RSA size from SubjectPublicKeyInfo or a bare RSAPublicKey", () => {
    expect(parseDkimKey(RSA2048_SPKI)).toEqual({ kind: "rsa", bits: 2048 });
    expect(parseDkimKey(RSA1024_SPKI)).toEqual({ kind: "rsa", bits: 1024 });
    expect(parseDkimKey(RSA2048_PKCS1, "RSA")).toEqual({ kind: "rsa", bits: 2048 });
  });

  it("accepts a 32-byte Ed25519 key and an empty (revoked) one", () => {
    expect(parseDkimKey(ED25519_RAW, "ed25519")).toEqual({ kind: "ed25519" });
    expect(parseDkimKey("")).toEqual({ kind: "revoked" });
  });

  it.each([
    ["non-base64 text", "!".repeat(300), "rsa"],
    ["base64 that isn't a key", "A".repeat(392), "rsa"],
    ["a truncated key", RSA2048_SPKI.slice(0, 200), "rsa"],
    ["an RSA key labelled Ed25519", RSA2048_SPKI, "ed25519"],
    ["an unknown key type", RSA2048_SPKI, "dsa"],
  ])("rejects %s", (_name, p, k) => {
    expect(parseDkimKey(p, k).kind).toBe("invalid");
  });
});

describe("parseHsts (#37)", () => {
  it("reads max-age and flags", () => {
    expect(parseHsts("max-age=31536000; includeSubDomains; preload")).toEqual({ valid: true, maxAge: 31536000, includeSubDomains: true, preload: true });
    expect(parseHsts('MAX-AGE="600"')).toEqual({ valid: true, maxAge: 600, includeSubDomains: false, preload: false });
    expect(parseHsts("max-age=63072000; someFutureDirective=1")).toMatchObject({ valid: true, maxAge: 63072000 });
  });

  it.each([
    ["max-age=31536000; max-age=0", "max-age appears more than once"],
    ["max-age=31536000; includeSubDomains; includeSubDomains", "includesubdomains appears more than once"],
    ["includeSubDomains", "max-age is missing"],
    ["max-age=1year", "max-age=1year isn't a number"],
    ["max-age=31536000; preload=yes", "preload takes no value"],
  ])("rejects %s", (header, why) => {
    expect(parseHsts(header)).toEqual({ valid: false, why });
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
    expect(judgeCerts([e(-90, -1)], NOW).status).toBe("skipped"); // none current: crt.sh may lag, so not graded
  });
});
