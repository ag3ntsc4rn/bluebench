import type { DomainReport } from "@bluebench/shared";
import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { App } from "../App";
import { BadgeSettings } from "../components/MyDomains";
import { DomainReportView, DomainsPage } from "./DomainsPage";

const text = (html: string) => html.replace(/<!-- -->/g, "").replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, "&");

const report: DomainReport = {
  ok: true,
  domain: "example.com",
  grade: "C",
  score: 72,
  checkedAt: "2026-10-11T12:00:00Z",
  cached: true,
  checks: [
    { id: "spf", status: "pass", summary: "One valid record.", facts: [{ label: "Record", value: "v=spf1 -all" }] },
    { id: "dmarc", status: "fail", summary: "No DMARC record.", fix: "Add a TXT record at _dmarc.example.com.", facts: [] },
    { id: "mx", status: "info", summary: "No mail servers.", facts: [] },
    { id: "cert", status: "skipped", summary: "Couldn't check certificates this time.", facts: [] },
  ],
};

describe("DomainsPage", () => {
  it("has a labelled input and a disabled button until there's a domain", () => {
    const html = renderToString(<DomainsPage />);
    expect(html).toContain('for="domain"');
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Check domain<\/button>/);
  });

  it("renders a shared link's page exactly like the pre-rendered checker (it hydrates that HTML)", () => {
    expect(renderToString(<DomainsPage initialDomain="example.com" />)).toBe(renderToString(<DomainsPage />));
    expect(renderToString(<App initialPath="/domain-checker/example.com" />)).toBe(renderToString(<App initialPath="/domain-checker" />));
  });
});

describe("DomainReportView", () => {
  const html = text(renderToString(<DomainReportView report={report} />));

  it("shows the grade with words, not just colour", () => {
    expect(html).toContain('aria-label="Grade C"');
    expect(html).toContain("Grade C (72/100). Fair. Some real gaps worth fixing.");
    expect(html).toContain("(cached; results refresh hourly)");
  });

  it("lists failures first, each with a status label and its fix", () => {
    expect(html.indexOf("DMARC")).toBeLessThan(html.indexOf("SPF"));
    expect(html).toContain(">Fail<");
    expect(html).toContain(">Pass<");
    expect(html).toContain(">Info<");
    expect(html).toContain(">Skipped<");
    expect(html).toContain("Fix: </span>Add a TXT record at _dmarc.example.com.");
  });

  it("offers a Share button for the report's link", () => {
    expect(html).toContain(">Share</span></button>");
  });

  it("never uses inline style attributes (CSP forbids them)", () => {
    expect(html).not.toMatch(/\\sstyle="/);
  });
});

describe("DomainReportView explanations", () => {
  it("offers a collapsed \"What's this?\" on every check", () => {
    const html = text(renderToString(<DomainReportView report={report} />));
    expect(html.match(/<summary[^>]*>What's this\?<\/summary>/g)).toHaveLength(report.checks.length);
    expect(html).toContain("It's what actually stops others sending email as you");
    expect(html).not.toMatch(/<details[^>]* open/);
  });
});

describe("BadgeSettings", () => {
  const saved = {
    id: "d1",
    domain: "example.com",
    verifyRecord: "bluebench-verify=x",
    verified: true,
    grade: "B" as const,
    score: 80,
    lastCheckedAt: null,
    certExpiresAt: null,
    lookalikes: [],
    lookalikesScannedAt: null,
    badgePublic: false,
    createdAt: "2026-10-01T00:00:00Z",
  };

  it("is off until the owner turns it on, with no snippet to copy", () => {
    const html = text(renderToString(<BadgeSettings d={saved} onChange={() => {}} />));
    expect(html).toContain("Badge off");
    expect(html).not.toContain("/api/badge/");
  });

  it("when on, shows the badge and Markdown and HTML that link to the report", () => {
    const html = text(renderToString(<BadgeSettings d={{ ...saved, badgePublic: true }} onChange={() => {}} />));
    expect(html).toContain("Badge on");
    expect(html).toContain('<img src="/api/badge/example.com.svg" alt="Bluebench grade for example.com" height="20"/>');
    expect(html).toContain("[![Bluebench grade for example.com](https://bluebench.dev/api/badge/example.com.svg)](https://bluebench.dev/domain-checker/example.com)");
    expect(html).toContain('&lt;a href="https://bluebench.dev/domain-checker/example.com"&gt;&lt;img src="https://bluebench.dev/api/badge/example.com.svg"'); // shown as code
  });
});
