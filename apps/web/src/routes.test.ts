import { detect, extractIndicators } from "@bluebench/shared";
import { describe, expect, it } from "vitest";
import { decodeJwt } from "./lib/jwt";
import { parseMime } from "./lib/mime";
import { collectLinks, readHtml, reportAttachment } from "./lib/triage";
import { ABOUT, ALERTS, DOMAINS, HOME, INTEL, metaFor, pageForPath, pathOf, PRIVACY, RESPOND, SETTINGS, SIGNIN, TOOLS } from "./routes";
import { RUNBOOKS } from "./runbooks";

const EXPECTED_KIND = {
  "ioc-lookup": "url",
  "ioc-extractor": "bulk",
  // A whole message: the paste box sees its headers (and offers triage).
  "phishing-triage": "email-headers",
  "jwt-decoder": "jwt",
  "email-header-analyzer": "email-headers",
  "base64-decoder": "base64",
  "url-decoder": "url",
} as const;

describe("routes", () => {
  it.each(TOOLS.map((t) => [t.slug, t] as const))("%s: example is detected as the right kind", (slug, tool) => {
    if (EXPECTED_KIND[slug] === "bulk") {
      // The extractor's example: several kinds of indicator, defanged, plus a file name that must be skipped.
      expect(new Set(extractIndicators(tool.example).map((e) => e.kind))).toEqual(new Set(["url", "domain", "ipv4", "email", "sha256"]));
      expect(extractIndicators(tool.example).some((e) => e.value.includes("invoice"))).toBe(false);
    } else expect(detect(tool.example)[0]?.kind).toBe(EXPECTED_KIND[slug]);
  });

  it("the phishing triage example exercises the whole flow, using only reserved names", () => {
    const tool = TOOLS.find((t) => t.slug === "phishing-triage")!;
    const msg = parseMime(tool.example);
    expect(msg.warnings).toEqual([]);
    expect(msg.text).toHaveLength(1);
    expect(msg.html).toHaveLength(1);
    const links = collectLinks(msg, msg.html.map(readHtml));
    expect(links.some((l) => l.findings.some((f) => f.title === "Link text shows a different site"))).toBe(true);
    const [attachment] = msg.attachments.map(reportAttachment);
    expect(attachment?.filename).toBe("payslip.pdf.html");
    expect(attachment?.findings.map((f) => f.title)).toContain("File name hides its real type");
    for (const host of tool.example.match(/[a-z0-9.-]+\.[a-z]{2,}(?=[/>"\s;]|$)/gim) ?? []) {
      if (/\.(html|pdf)$/i.test(host)) continue;
      expect(host, host).toMatch(/(^|\.)example\.(com|net|org)$|\.test$/i);
    }
  });

  it("every tool has its own placeholder", () => {
    expect(new Set(TOOLS.map((t) => t.placeholder)).size).toBe(TOOLS.length);
  });

  it("the JWT example decodes", () => {
    expect(decodeJwt(TOOLS.find((t) => t.slug === "jwt-decoder")!.example)).not.toBeNull();
  });

  it("every page has a unique path and title, and a search-friendly description", () => {
    const pages = [HOME, PRIVACY, ABOUT, SETTINGS, DOMAINS, ALERTS, SIGNIN, RESPOND, INTEL, ...TOOLS, ...RUNBOOKS];
    expect(new Set(pages.map((p) => p.path)).size).toBe(pages.length);
    expect(new Set(pages.map((p) => p.title)).size).toBe(pages.length);
    for (const p of pages) {
      expect(p.title.length, p.path).toBeLessThanOrEqual(80);
      expect(p.description.length, p.path).toBeGreaterThanOrEqual(80);
      expect(p.description.length, p.path).toBeLessThanOrEqual(170);
    }
  });

  it("maps paths to pages, tolerating a trailing slash", () => {
    expect(pageForPath("/")).toEqual({ kind: "home" });
    expect(pageForPath("/privacy/")).toEqual({ kind: "privacy" });
    expect(pageForPath("/jwt-decoder")).toMatchObject({ kind: "tool", tool: { slug: "jwt-decoder" } });
    expect(pageForPath("/phishing-triage")).toMatchObject({ kind: "tool", tool: { slug: "phishing-triage" } });
    expect(pageForPath("/domain-checker")).toEqual({ kind: "domains" });
    expect(pageForPath("/alerts")).toEqual({ kind: "alerts" });
    expect(pageForPath("/signin")).toEqual({ kind: "signin" });
    expect(pageForPath("/about")).toEqual({ kind: "about" });
    expect(pageForPath("/respond")).toEqual({ kind: "respond" });
    expect(pageForPath("/exploited-vulnerabilities")).toEqual({ kind: "intel" });
    expect(pageForPath("/respond/lost-laptop/")).toMatchObject({ kind: "runbook", runbook: { slug: "lost-laptop" } });
    expect(pageForPath("/respond/nope")).toEqual({ kind: "notfound" });
    expect(pageForPath("/settings/")).toEqual({ kind: "settings" });
    expect(pageForPath("/wp-admin")).toEqual({ kind: "notfound" });
  });

  it("maps a shareable report link to the domain checker for that domain", () => {
    expect(pageForPath("/domain-checker/Example.COM/")).toEqual({ kind: "domains", domain: "example.com" });
    expect(pageForPath("/domain-checker/203.0.113.7")).toEqual({ kind: "notfound" });
    expect(pageForPath("/domain-checker/a/b")).toEqual({ kind: "notfound" });
    expect(pageForPath("/domain-checker/%E0%A4%A")).toEqual({ kind: "notfound" });
    const page = { kind: "domains", domain: "example.com" } as const;
    expect(pathOf(page)).toBe("/domain-checker/example.com");
    expect(metaFor(page).title).toBe("example.com security report card | Bluebench");
  });
});
