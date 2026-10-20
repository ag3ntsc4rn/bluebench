import { renderToString } from "react-dom/server";
import { afterEach, describe, expect, it } from "vitest";
import { clearHandOff, handOffMessage } from "../lib/triage";
import { TOOLS } from "../routes";
import { TriagePage } from "./TriagePage";

const tool = TOOLS.find((t) => t.slug === "phishing-triage")!;
const render = () =>
  renderToString(<TriagePage heading={tool.h1} lead={tool.lead} example={tool.example} placeholder={tool.placeholder} />)
    .replace(/<!-- -->/g, "")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&amp;/g, "&");

afterEach(clearHandOff);

describe("TriagePage", () => {
  it("starts empty, with a labelled box, a file picker and an example", () => {
    const html = render();
    expect(html).toMatch(/<label for="triage-paste"[^>]*>Raw message/);
    expect(html).toMatch(/<label[^>]*>Choose .eml file<input type="file"/);
    expect(html).toContain("Try an example");
    expect(html).not.toContain("Summary");
  });

  it("triages a message handed over from Lookup", () => {
    handOffMessage(tool.example);
    const html = render();
    expect(html).toContain("Copy as ticket note");
    expect(html).toContain("Link text shows a different site");
    expect(html).toContain("payslip.pdf.html");
    expect(html).toContain("File name hides its real type");
    expect(html).toContain("SPF soft fail"); // header analysis
    expect(html).toContain("Check reputation for");
    expect(html).toContain('href="/respond/phishing-link-clicked"');
    // The email's own HTML is never put into the page: its link exists only as text.
    expect(html).not.toContain('<a href="https://example-payroll.test');
    expect(html).not.toMatch(/\sstyle="/);
  });
});
