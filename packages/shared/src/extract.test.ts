import { describe, expect, it } from "vitest";
import { exportVerdict, extractedKey, extractIndicators, stixPattern, toCsv, toStixBundle, type Extracted } from "./extract.ts";

const kinds = (text: string) => extractIndicators(text).map((e) => `${e.kind}:${e.value}`);

describe("extractIndicators", () => {
  it("pulls every kind out of a report, refanged and grouped", () => {
    const report = `Phishing kit at hxxps://login-example[.]com/verify?id=1 sent from 198.51.100.7 and 2001:db8::1.
      Callback domain: evil-cdn[.]net. Contact attacker[@]bad[.]example.
      Payload SHA-256 ${"a".repeat(64)}, MD5 ${"b".repeat(32)}.`;
    expect(kinds(report)).toEqual([
      "url:https://login-example.com/verify?id=1",
      "domain:evil-cdn.net",
      "ipv4:198.51.100.7",
      "ipv6:2001:db8::1",
      "email:attacker@bad.example",
      `sha256:${"a".repeat(64)}`,
      `md5:${"b".repeat(32)}`,
    ]);
  });

  it("doesn't list a URL's or email's host again", () => {
    expect(kinds("https://evil.example/a and someone@evil.example")).toEqual(["url:https://evil.example/a", "email:someone@evil.example"]);
  });

  it("de-duplicates, ignoring case and defanging differences", () => {
    expect(kinds("EVIL.com evil[.]com evil.com")).toEqual(["domain:evil.com"]);
  });

  it("skips file names, version numbers, times, MACs and sentence run-ons", () => {
    const prose = "Opened invoice.pdf and ran update.exe (node.js). Version 1.2.3.4.5 at 12:30:45, MAC 00:1a:2b:3c:4d:5e. The end.Then nothing.";
    expect(kinds(prose)).toEqual([]);
  });

  it("strips trailing punctuation from URLs", () => {
    expect(kinds("See (https://evil.example/path).")).toEqual(["url:https://evil.example/path"]);
  });

  it("caps the number of results", () => {
    const many = Array.from({ length: 30 }, (_, i) => `10.0.0.${i}`).join(" ");
    expect(extractIndicators(many, 10)).toHaveLength(10);
  });
});

describe("exports", () => {
  const items: Extracted[] = [
    { kind: "url", value: "https://evil.example/a,b" },
    { kind: "email", value: "=cmd@evil.example" },
    { kind: "sha1", value: "c".repeat(40) },
  ];

  it("writes CSV with escaping and formula-injection protection", () => {
    const csv = toCsv(items, (i) => i.value.replace(/\./g, "[.]"));
    expect(csv.split("\r\n")).toEqual([
      "type,value,defanged,verdict,listed_by",
      'url,"https://evil.example/a,b","https://evil[.]example/a,b",,',
      "email,'=cmd@evil.example,'=cmd@evil[.]example,,",
      `sha1,${"c".repeat(40)},${"c".repeat(40)},,`,
      "",
    ]);
  });

  it("writes STIX patterns for each kind, escaping quotes", () => {
    expect(stixPattern({ kind: "ipv4", value: "198.51.100.7" })).toBe("[ipv4-addr:value = '198.51.100.7']");
    expect(stixPattern({ kind: "sha256", value: "d".repeat(64) })).toBe(`[file:hashes.'SHA-256' = '${"d".repeat(64)}']`);
    expect(stixPattern({ kind: "md5", value: "e".repeat(32) })).toBe(`[file:hashes.MD5 = '${"e".repeat(32)}']`);
    expect(stixPattern({ kind: "url", value: "https://x.example/it's\\here" })).toBe("[url:value = 'https://x.example/it\\'s\\\\here']");
  });

  it("writes a STIX 2.1 bundle of indicators", () => {
    let n = 0;
    const bundle = JSON.parse(toStixBundle(items, new Date("2026-10-13T12:00:00Z"), () => `00000000-0000-4000-8000-${String(n++).padStart(12, "0")}`));
    expect(bundle).toMatchObject({ type: "bundle", id: "bundle--00000000-0000-4000-8000-000000000003" });
    expect(bundle.objects).toHaveLength(3);
    expect(bundle.objects[0]).toEqual({
      type: "indicator",
      spec_version: "2.1",
      id: "indicator--00000000-0000-4000-8000-000000000000",
      created: "2026-10-13T12:00:00.000Z",
      modified: "2026-10-13T12:00:00.000Z",
      name: "https://evil.example/a,b",
      pattern: "[url:value = 'https://evil.example/a,b']",
      pattern_type: "stix",
      pattern_version: "2.1",
      valid_from: "2026-10-13T12:00:00.000Z",
    });
  });
});

describe("TLD check", () => {
  it("keeps real domains, including abused TLDs, and drops file and code names", () => {
    expect(kinds("evil.top bad.xyz payload.zip phish.pl x.cc")).toEqual(["domain:evil.top", "domain:bad.xyz", "domain:payload.zip", "domain:phish.pl", "domain:x.cc"]);
    expect(kinds("login.cgi ld.so array.pop telerik.web.ui com.sun.org.glassfish.external README.md setup.py")).toEqual([]);
  });
});

describe("exports with reputation", () => {
  const url: Extracted = { kind: "url", value: "https://evil.example/" };
  const sb = { source: "safebrowsing" as const, status: "listed" as const, summary: "", facts: [] };
  const uh = (status: "listed" | "not-listed") => ({ source: "urlhaus" as const, status, summary: "", facts: [] });

  it("never lets Safe Browsing decide an exported verdict", () => {
    expect(exportVerdict({ sources: [sb, uh("not-listed")] })).toEqual({ verdict: "not-listed", listedBy: [] });
    expect(exportVerdict({ sources: [sb, uh("listed")] })).toEqual({ verdict: "listed", listedBy: ["URLhaus"] });
    expect(exportVerdict({ sources: [sb] })).toEqual({ verdict: "incomplete", listedBy: [] });
  });

  it("adds verdict columns to CSV and labels listed indicators in STIX", () => {
    const verdicts = new Map([[extractedKey(url), exportVerdict({ sources: [uh("listed")] })]]);
    expect(toCsv([url], (i) => i.value, verdicts).split("\r\n")[1]).toBe("url,https://evil.example/,https://evil.example/,listed,URLhaus");
    const [obj] = JSON.parse(toStixBundle([url], new Date("2026-10-13T12:00:00Z"), () => "00000000-0000-4000-8000-000000000000", verdicts)).objects;
    expect(obj).toMatchObject({ indicator_types: ["malicious-activity"], description: "Listed by URLhaus (checked with Bluebench on 2026-10-13)." });
    const [plain] = JSON.parse(toStixBundle([url])).objects;
    expect(plain.indicator_types).toBeUndefined();
  });
});
