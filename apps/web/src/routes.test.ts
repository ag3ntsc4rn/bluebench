import { detect } from "@bluebench/shared";
import { describe, expect, it } from "vitest";
import { decodeJwt } from "./lib/jwt";
import { ABOUT, ALERTS, DOMAINS, HOME, pageForPath, PRIVACY, RESPOND, SETTINGS, SIGNIN, TOOLS } from "./routes";
import { RUNBOOKS } from "./runbooks";

const EXPECTED_KIND = {
  "ioc-lookup": "url",
  "jwt-decoder": "jwt",
  "email-header-analyzer": "email-headers",
  "base64-decoder": "base64",
  "url-decoder": "url",
} as const;

describe("routes", () => {
  it.each(TOOLS.map((t) => [t.slug, t] as const))("%s: example is detected as the right kind", (slug, tool) => {
    expect(detect(tool.example)[0]?.kind).toBe(EXPECTED_KIND[slug]);
  });

  it("every tool has its own placeholder", () => {
    expect(new Set(TOOLS.map((t) => t.placeholder)).size).toBe(TOOLS.length);
  });

  it("the JWT example decodes", () => {
    expect(decodeJwt(TOOLS.find((t) => t.slug === "jwt-decoder")!.example)).not.toBeNull();
  });

  it("every page has a unique path and title, and a search-friendly description", () => {
    const pages = [HOME, PRIVACY, ABOUT, SETTINGS, DOMAINS, ALERTS, SIGNIN, RESPOND, ...TOOLS, ...RUNBOOKS];
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
    expect(pageForPath("/domain-checker")).toEqual({ kind: "domains" });
    expect(pageForPath("/alerts")).toEqual({ kind: "alerts" });
    expect(pageForPath("/signin")).toEqual({ kind: "signin" });
    expect(pageForPath("/about")).toEqual({ kind: "about" });
    expect(pageForPath("/respond")).toEqual({ kind: "respond" });
    expect(pageForPath("/respond/lost-laptop/")).toMatchObject({ kind: "runbook", runbook: { slug: "lost-laptop" } });
    expect(pageForPath("/respond/nope")).toEqual({ kind: "notfound" });
    expect(pageForPath("/settings/")).toEqual({ kind: "settings" });
    expect(pageForPath("/wp-admin")).toEqual({ kind: "notfound" });
  });
});
