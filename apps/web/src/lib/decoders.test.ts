import { describe, expect, it } from "vitest";
import { decodeBase64, hexDump } from "./base64";
import { formatDuration } from "./findings";
import { decodeJwt } from "./jwt";
import { analyzeUrl, decodeLayers, safeDecode } from "./url";

const b64url = (o: unknown) => btoa(JSON.stringify(o)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
const jwt = (header: unknown, payload: unknown, sig = "c2ln") => `${b64url(header)}.${b64url(payload)}.${sig}`;
const NOW = Date.UTC(2024, 9, 8, 12, 0, 0);

describe("decodeJwt", () => {
  it("decodes header, payload and time claims", () => {
    const d = decodeJwt(jwt({ alg: "HS256", typ: "JWT" }, { sub: "42", iat: NOW / 1000 - 3600, exp: NOW / 1000 + 7200 }), NOW)!;
    expect(d.header).toEqual({ alg: "HS256", typ: "JWT" });
    expect(d.payload).toMatchObject({ sub: "42" });
    expect(d.times.map((t) => [t.claim, t.display])).toEqual([
      ["iat", "2024-10-08 11:00:00 UTC (1 h ago)"],
      ["exp", "2024-10-08 14:00:00 UTC (in 2 h)"],
    ]);
    expect(d.findings.map((f) => f.title)).toEqual(["Signature not verified"]);
  });

  it("flags alg none, expiry, not-before and missing exp", () => {
    const none = decodeJwt(jwt({ alg: "none" }, { sub: "x" }, ""), NOW)!;
    expect(none.findings.map((f) => [f.severity, f.title])).toEqual([
      ["critical", 'Algorithm is "none"'],
      ["info", "No expiry"],
      ["info", "Signature not verified"],
    ]);
    const expired = decodeJwt(jwt({ alg: "RS256" }, { exp: NOW / 1000 - 90, nbf: NOW / 1000 + 60 }), NOW)!;
    expect(expired.findings.map((f) => f.title)).toEqual(["Not valid yet", "Expired", "Signature not verified"]);
  });

  it("returns null for garbage", () => {
    expect(decodeJwt("not.a.jwt")).toBeNull();
  });
});

describe("decodeBase64", () => {
  it("decodes UTF-8 and UTF-16LE text", () => {
    expect(decodeBase64("aGVsbG8gd29ybGQ=")).toEqual({ size: 11, text: "hello world", encoding: "UTF-8", truncated: false });
    expect(decodeBase64("VwByAGkAdABlAC0ASABvAHMAdAAgACIAaABpACIA")).toMatchObject({ text: 'Write-Host "hi"', encoding: "UTF-16LE" });
  });

  it("sniffs binaries and returns a hex dump", () => {
    const d = decodeBase64("TVqQAAMAAAAEAAAA//8AAA==")!;
    expect(d.fileType).toBe("Windows executable (PE)");
    expect(d.hexDump).toBe("00000000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00  MZ..............");
    expect(d.text).toBeUndefined();
  });

  it("truncates long hex dumps", () => {
    expect(hexDump(new Uint8Array(1000)).split("\n")).toHaveLength(32);
    expect(decodeBase64(btoa(String.fromCharCode(...new Uint8Array(600).fill(1))))?.truncated).toBe(true);
  });
});

describe("URL tools", () => {
  it("decodes safely, including broken sequences and double encoding", () => {
    expect(safeDecode("a%20b%ZZ%E2%9C%93")).toBe("a b%ZZ✓");
    expect(safeDecode("a+b", true)).toBe("a b");
    expect(decodeLayers("%253Cb%253E")).toEqual(["%253Cb%253E", "%3Cb%3E", "<b>"]);
  });

  it("breaks a URL into parts", () => {
    const a = analyzeUrl("https://example.com/a%20b?q=1&next=x#frag")!;
    expect(a).toMatchObject({ scheme: "https", host: "example.com", path: "/a b", fragment: "frag" });
    expect(a.params).toEqual([
      ["q", "1"],
      ["next", "x"],
    ]);
    expect(a.findings).toEqual([]);
  });

  it("flags suspicious URLs", () => {
    const titles = (u: string) => analyzeUrl(u)!.findings.map((f) => f.title);
    expect(titles("http://paypal.com@198.51.100.7:8080/")).toEqual([
      "Text before @ in the address",
      "Links to a bare IP address",
      "Non-standard port",
      "Not encrypted",
    ]);
    expect(titles("https://xn--pypal-4ve.com/?url=https://evil.example/")).toEqual([
      "Internationalised domain (xn--)",
      "Contains another URL",
    ]);
    expect(titles("https://login.secure.account.example.com.evil.io/")).toEqual(["Many subdomains"]);
  });
});

describe("formatDuration", () => {
  it.each([
    [0, "0 s"],
    [59, "59 s"],
    [61, "1 min 1 s"],
    [3600, "1 h"],
    [3720, "1 h 2 min"],
    [-5, "−5 s"],
  ])("%d → %s", (s, out) => expect(formatDuration(s)).toBe(out));
});
