import type { DomainReport, LookupResponse } from "@bluebench/shared";
import { describe, expect, it } from "vitest";
import { analyzeHeaders } from "./email-headers";
import { decodeJwt } from "./jwt";
import { defangHost, defangText, defangUrl, summarizeDomain, summarizeHeaders, summarizeJwt, summarizeLookup, summarizeUrl } from "./summaries";
import { analyzeUrl } from "./url";

const NOW = Date.parse("2026-10-11T18:40:00Z");
/** No live link should survive in shared text. */
const noLiveLinks = (text: string) => expect(text).not.toMatch(/\bhttps?:\/\/(?!(urlhaus|threatfox|bazaar)\.abuse\.ch|bluebench\.dev)/i);

describe("defanging", () => {
  it("defangs hosts, URLs and embedded URLs", () => {
    expect(defangHost("evil.example")).toBe("evil[.]example");
    expect(defangHost("203.0.113.7")).toBe("203[.]0[.]113[.]7");
    expect(defangUrl("https://evil.example:8443/a.php?x=1.2")).toBe("hxxps://evil[.]example:8443/a[.]php?x=1.2");
    expect(defangUrl("http://user@evil.example/")).toBe("hxxp://user@evil[.]example/");
    expect(defangText("go to https://x.test/a now")).toBe("go to hxxps://x[.]test/a now");
    expect(defangText("from 198.51.100.7 via mail.evil.example")).toBe("from 198[.]51[.]100[.]7 via mail[.]evil[.]example");
    expect(defangText("Wait 1.5 s, e.g. now")).toBe("Wait 1.5 s, e.g. now");
  });
});

describe("summarizeLookup", () => {
  const r: LookupResponse = {
    ok: true,
    kind: "url",
    value: "https://evil.example/login",
    verdict: "listed",
    sources: [
      { source: "urlhaus", status: "listed", summary: "Listed as a malware distribution URL.", facts: [{ label: "Threat", value: "malware_download" }], link: "https://urlhaus.abuse.ch/url/42/" },
      { source: "safebrowsing", status: "listed", summary: "Suspected phishing or deceptive site. Advisory provided by Google.", facts: [], link: "https://developers.google.com/safe-browsing/v4/advisory" },
    ],
  };
  const text = summarizeLookup(r, NOW);

  it("leads with the defanged indicator and the verdict", () => {
    expect(text.split("\n").slice(0, 2)).toEqual(["Reputation: hxxps://evil[.]example/login (URL)", "Verdict: Listed by at least one source"]);
    noLiveLinks(text);
  });

  it("lists each source, keeps abuse.ch links, and carries Google's attribution and disclaimer", () => {
    expect(text).toContain("- URLhaus: Listed. Listed as a malware distribution URL.");
    expect(text).toContain("    Threat: malware_download");
    expect(text).toContain("https://urlhaus.abuse.ch/url/42/");
    expect(text).toContain("- Google Safe Browsing: Suspected.");
    expect(text).toContain("Advisory provided by Google. Protection isn't perfect");
    expect(text).toContain("Checked 2026-10-11 18:40:00 UTC, via bluebench.dev");
  });
});

describe("summarizeDomain", () => {
  it("shows grade, failures first, and each fix", () => {
    const r: DomainReport = {
      ok: true,
      domain: "example.com",
      grade: "C",
      score: 72,
      checkedAt: "2026-10-11T18:40:00Z",
      checks: [
        { id: "spf", status: "pass", summary: "One valid record.", facts: [] },
        { id: "dmarc", status: "fail", summary: "No DMARC record.", fix: "Add a TXT record at _dmarc.example.com.", facts: [] },
      ],
    };
    const text = summarizeDomain(r);
    expect(text).toContain("Grade: C (72/100)");
    expect(text.indexOf("DMARC: Fail")).toBeLessThan(text.indexOf("SPF: Pass"));
    expect(text).toContain("    Fix: Add a TXT record at _dmarc.example.com.");
  });
});

describe("summarizeHeaders", () => {
  it("summarises sender, authentication, red flags and path with addresses defanged", () => {
    const a = analyzeHeaders(
      [
        "Received: from evil.example (evil.example [198.51.100.7]) by mx.example.org; Tue, 08 Oct 2024 10:00:05 +0000",
        "Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=evil.example; dmarc=fail header.from=bank.example",
        'From: "Your Bank" <alerts@bank.example>',
        "Reply-To: collect@evil.example",
        "Subject: Verify now",
      ].join("\n"),
    );
    const text = summarizeHeaders(a, NOW);
    expect(text).toContain('From: "Your Bank" <alerts@bank[.]example>');
    expect(text).toContain("Reply-To: <collect@evil[.]example>");
    expect(text).toContain("- SPF: fail (evil[.]example)");
    expect(text).toMatch(/- Red flag: /);
    expect(text).toContain("[198[.]51[.]100[.]7]");
    expect(text).not.toContain("evil.example");
  });
});

describe("summarizeJwt and summarizeUrl", () => {
  it("includes JWT findings, header and payload", () => {
    const text = summarizeJwt(decodeJwt("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.")!);
    expect(text).toContain('Red flag: Algorithm is "none"');
    expect(text).toContain('"sub": "x"');
    expect(text).toContain("Signature not verified");
  });

  it("defangs the URL and any URL hidden in its parameters", () => {
    const text = summarizeUrl(analyzeUrl("https://example.com/r?to=https%3A%2F%2Fevil.example%2Flogin")!);
    expect(text).toContain("URL: hxxps://example[.]com/r?to=");
    expect(text).toContain("- to = hxxps://evil[.]example/login");
    expect(text).not.toContain("evil.example");
    noLiveLinks(text);
  });
});
