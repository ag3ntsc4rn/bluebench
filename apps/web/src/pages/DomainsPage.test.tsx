import type { DomainReport } from "@bluebench/shared";
import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
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

  it("never uses inline style attributes (CSP forbids them)", () => {
    expect(html).not.toMatch(/\\sstyle="/);
  });
});
