import type { LookupResponse } from "@bluebench/shared";
import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Reputation, ReputationResult } from "./Reputation";

const text = (html: string) => html.replace(/<!-- -->/g, "").replace(/&#x27;/g, "'").replace(/&amp;/g, "&");

describe("Reputation", () => {
  it("only offers a button and says what will be sent", () => {
    const html = text(renderToString(<Reputation kind="sha1" value={"a".repeat(40)} />));
    expect(html).toContain("Check reputation");
    expect(html).toContain("Checks MalwareBazaar. Only this indicator is sent to our server, and it isn't logged.");
  });
});

describe("ReputationResult", () => {
  const result: LookupResponse = {
    ok: true,
    kind: "url",
    value: "https://phish.example/",
    verdict: "listed",
    sources: [
      { source: "urlhaus", status: "not-listed", summary: "Not in URLhaus.", facts: [], cached: true },
      {
        source: "safebrowsing",
        status: "listed",
        summary: "Suspected phishing or deceptive site. Advisory provided by Google.",
        facts: [{ label: "Warnings", value: "Suspected phishing or deceptive site" }],
        link: "https://developers.google.com/safe-browsing/v4/advisory",
      },
      { source: "threatfox", status: "skipped", summary: "Busy right now.", facts: [], stale: false },
    ],
  };

  it("shows the merged verdict with a text label, and hedges Safe Browsing", () => {
    const html = text(renderToString(<ReputationResult result={result} />));
    expect(html).toContain(">Listed<");
    expect(html).toContain(">Suspected<");
    expect(html).toContain(">Skipped<");
    expect(html).toContain("Recent cached result.");
    expect(html).toContain("Advisory provided by Google");
    expect(html).toContain("some risky sites may not be identified");
    expect(html).not.toMatch(/\sstyle="/);
  });

  it("never calls a not-listed result safe", () => {
    const html = text(renderToString(<ReputationResult result={{ ...result, verdict: "not-listed", sources: [result.sources[0]!] }} />));
    expect(html).toContain("isn't proof it's safe");
    expect(html).not.toContain("Advisory provided by Google"); // no Safe Browsing result shown
  });
});
