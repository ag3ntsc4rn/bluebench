import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { SECURITY_HEADERS } from "@bluebench/shared";

/**
 * When the Worker fetches its own domain (a domain report on bluebench.dev), Cloudflare routes the
 * request back into the Worker instead of to static assets. It must then behave like the edge does.
 */
describe("non-API requests that reach the Worker", () => {
  it("redirect plain HTTP to HTTPS", async () => {
    const res = await exports.default.fetch("http://bluebench.dev/some/page?x=1", { redirect: "manual" });
    expect(res.status).toBe(301);
    expect(res.headers.get("location")).toBe("https://bluebench.dev/some/page?x=1");
  });

  it("serve static assets with the full security headers, including HSTS", async () => {
    const res = await exports.default.fetch("https://bluebench.dev/");
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) expect(res.headers.get(name), name).toBe(value);
    expect(res.headers.get("strict-transport-security")).toMatch(/max-age=\d{8}/);
  });

  it("leave API routes to the API", async () => {
    const res = await exports.default.fetch("https://bluebench.dev/api/health");
    expect(await res.json()).toEqual({ ok: true });
  });
});
