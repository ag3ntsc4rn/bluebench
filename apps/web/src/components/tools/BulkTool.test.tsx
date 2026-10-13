import type { LookupResponse } from "@bluebench/shared";
import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { BulkTool, checkable, defangExtracted, resultBadge } from "./BulkTool";

describe("defangExtracted", () => {
  it("makes links, hosts and addresses unclickable, and leaves hashes alone", () => {
    expect(defangExtracted({ kind: "url", value: "https://evil.top/a" })).toBe("hxxps://evil[.]top/a");
    expect(defangExtracted({ kind: "domain", value: "evil.top" })).toBe("evil[.]top");
    expect(defangExtracted({ kind: "ipv4", value: "198.51.100.7" })).toBe("198[.]51[.]100[.]7");
    expect(defangExtracted({ kind: "email", value: "a@evil.top" })).toBe("a@evil[.]top");
    expect(defangExtracted({ kind: "md5", value: "a".repeat(32) })).toBe("a".repeat(32));
  });
});

describe("checkable", () => {
  it("skips email addresses and private or reserved IPs", () => {
    expect(checkable({ kind: "domain", value: "evil.top" })).toBe(true);
    expect(checkable({ kind: "ipv4", value: "8.8.8.8" })).toBe(true);
    expect(checkable({ kind: "ipv4", value: "10.0.0.5" })).toBe(false);
    expect(checkable({ kind: "email", value: "a@evil.top" })).toBe(false);
  });
});

describe("resultBadge", () => {
  const res = (sources: LookupResponse["sources"], verdict: LookupResponse["verdict"]): LookupResponse => ({ ok: true, kind: "url", value: "x", verdict, sources });
  const sb = { source: "safebrowsing" as const, status: "listed" as const, summary: "", facts: [] };
  const uh = { source: "urlhaus" as const, status: "listed" as const, summary: "", facts: [] };

  it("hedges a Safe Browsing-only match, as single lookups do", () => {
    expect(resultBadge(res([sb], "listed"))).toEqual({ tone: "critical", label: "Suspected" });
    expect(resultBadge(res([sb, uh], "listed"))).toEqual({ tone: "critical", label: "Listed" });
    expect(resultBadge(res([], "not-listed")).label).toBe("Not listed");
    expect(resultBadge({ ok: false, kind: "domain", value: "x", error: "daily-limit", message: "" }).label).toBe("Not checked");
  });
});

describe("BulkTool", () => {
  it("offers to check what can be checked, and says what's skipped and what it costs", () => {
    const html = renderToString(
      <BulkTool
        items={[
          { kind: "domain", value: "evil.top" },
          { kind: "ipv4", value: "10.0.0.5" },
          { kind: "email", value: "a@evil.top" },
          { kind: "sha256", value: "a".repeat(64) },
        ]}
        onUseAsInput={() => {}}
      />,
    ).replace(/<!-- -->/g, "").replace(/&#x27;/g, "'");
    expect(html).toContain("Check reputation for 2");
    expect(html).toContain("2 can't be checked (email addresses and private IPs)");
    expect(html).toContain("100 a day, or 300 signed in");
    expect(html).toContain("Exported verdicts leave out Google Safe Browsing");
  });
});
