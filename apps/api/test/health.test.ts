import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { SECURITY_HEADERS } from "@bluebench/shared";

function expectSecurityHeaders(res: Response) {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    expect(res.headers.get(name), name).toBe(value);
  }
}

describe("GET /api/health", () => {
  it("returns { ok: true } with security headers", async () => {
    const res = await exports.default.fetch("https://bluebench.dev/api/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expectSecurityHeaders(res);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });
});

describe("unknown API routes", () => {
  it("return a JSON 404 with security headers", async () => {
    const res = await exports.default.fetch("https://bluebench.dev/api/nope");
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ ok: false, error: "Not found" });
    expectSecurityHeaders(res);
  });
});
