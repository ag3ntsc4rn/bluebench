import { describe, expect, it } from "vitest";
import { SECURITY_HEADERS, formatHeadersFile } from "./security-headers.ts";

describe("SECURITY_HEADERS", () => {
  it("includes every header required by CLAUDE.md", () => {
    expect(SECURITY_HEADERS["Content-Security-Policy"]).toContain("default-src 'self'");
    expect(SECURITY_HEADERS["Content-Security-Policy"]).toContain("frame-ancestors 'none'");
    expect(SECURITY_HEADERS["Strict-Transport-Security"]).toMatch(/max-age=\d{8,}/);
    expect(SECURITY_HEADERS["X-Content-Type-Options"]).toBe("nosniff");
    expect(SECURITY_HEADERS["Referrer-Policy"]).toBe("no-referrer");
    expect(SECURITY_HEADERS["Permissions-Policy"]).toContain("camera=()");
  });

  it("does not allow inline or eval scripts", () => {
    expect(SECURITY_HEADERS["Content-Security-Policy"]).not.toMatch(/unsafe-(inline|eval)/);
  });

  it("allows Turnstile's script and frame, OTX for bring-your-own-key calls, and nothing else third-party", () => {
    const csp = SECURITY_HEADERS["Content-Security-Policy"]!;
    expect(csp).toContain("script-src 'self' https://challenges.cloudflare.com;");
    expect(csp).toContain("frame-src https://challenges.cloudflare.com;");
    expect(csp).toContain("connect-src 'self' https://otx.alienvault.com;");
    const origins = csp.match(/https:\/\/[^\s;]+/g) ?? [];
    expect(new Set(origins)).toEqual(new Set(["https://challenges.cloudflare.com", "https://otx.alienvault.com"]));
  });
});

describe("formatHeadersFile", () => {
  it("applies every header to all paths", () => {
    const file = formatHeadersFile();
    const lines = file.trimEnd().split("\n");
    expect(lines[0]).toBe("/*");
    expect(lines).toHaveLength(Object.keys(SECURITY_HEADERS).length + 1);
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      expect(lines).toContain(`  ${name}: ${value}`);
    }
  });
});
