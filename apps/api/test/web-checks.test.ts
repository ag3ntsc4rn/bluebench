import { describe, expect, it } from "vitest";
import { headersCheck, hstsCheck, httpsCheck, type WebProbe } from "../src/domain/web.ts";

/** A site whose home page answers 200 over HTTPS with `headers`, and plain HTTP as given. */
const probe = (headers: Record<string, string>, http: WebProbe["http"] = { reachesHttps: true, trail: "301 → https://x.example/" }): WebProbe => ({
  hasAddress: true,
  https: { hops: [{ url: "https://x.example/", status: 200, headers: new Headers(headers) }], redirectLimitHit: false },
  http,
});

describe("headersCheck (#35)", () => {
  it("doesn't credit the reviewer's present-but-useless headers", () => {
    const c = headersCheck(
      probe({
        "content-security-policy": "default-src * 'unsafe-inline' 'unsafe-eval'",
        "x-content-type-options": "not-nosniff",
        "x-frame-options": "ALLOWALL",
        "referrer-policy": "definitely-invalid",
        "permissions-policy": "*",
      }),
    );
    expect(c.status).toBe("fail");
    expect(c.summary).toBe("Only 0 of 5 recommended security headers are set to protective values.");
    expect(c.facts.map((f) => f.value)).toEqual([
      "ineffective: allows scripts from anywhere (*)",
      'ineffective: "not-nosniff" isn\'t nosniff',
      'ineffective: X-Frame-Options "ALLOWALL" isn\'t DENY or SAMEORIGIN',
      'ineffective: "definitely-invalid" isn\'t a valid policy',
      'ineffective: "*" isn\'t a valid policy',
    ]);
  });

  it("passes protective values, case- and whitespace-insensitively", () => {
    const c = headersCheck(
      probe({
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": " NoSniff ",
        "referrer-policy": "no-referrer, strict-origin-when-cross-origin",
        "permissions-policy": "camera=()",
      }),
    );
    expect(c).toMatchObject({ status: "pass", summary: "All five recommended security headers are set to protective values." });
  });

  it("counts leaky referrer policies and frame-ancestors * as ineffective", () => {
    const c = headersCheck(probe({ "content-security-policy": "default-src 'self'; frame-ancestors *", "referrer-policy": "unsafe-url" }));
    expect(c.facts.find((f) => f.label === "Framing")!.value).toContain("frame-ancestors * allows any site");
    expect(c.facts.find((f) => f.label === "Referrer-Policy")!.value).toContain("unsafe-url sends full URLs");
  });
});

describe("httpsCheck (#36)", () => {
  it("passes only when plain HTTP refused the connection", () => {
    expect(httpsCheck(probe({}, { error: "Couldn't connect", closed: true }), "x.example")).toMatchObject({
      status: "pass",
      summary: "Loads over HTTPS, and nothing is served over plain HTTP.",
    });
  });

  it.each([
    ["a timeout", "Timed out after 5 seconds"],
    ["an exhausted budget", "budget"],
    ["a blocked redirect", "Refusing to connect to a non-public address (private)"],
  ])("doesn't grade %s as a closed port", (_name, error) => {
    const c = httpsCheck(probe({}, { error, closed: false }), "x.example");
    expect(c.status).toBe("skipped");
    expect(c.summary).not.toContain("nothing is served over plain HTTP");
  });
});

describe("hstsCheck (#37)", () => {
  it("fails a header browsers ignore because max-age is repeated", () => {
    const c = hstsCheck(probe({ "strict-transport-security": "max-age=31536000; max-age=0" }));
    expect(c).toMatchObject({ status: "fail", summary: "The HSTS header is malformed (max-age appears more than once), so browsers ignore it." });
  });

  it("still passes a valid year-long header", () => {
    expect(hstsCheck(probe({ "strict-transport-security": "max-age=31536000; includeSubDomains" })).status).toBe("pass");
  });
});
