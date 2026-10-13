import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { KEV_KV_KEYS, SECURITY_HEADERS, type ApiError, type KevResponse } from "@bluebench/shared";

const get = (path: string) => exports.default.fetch(`https://bluebench.dev${path}`, { headers: { "cf-connecting-ip": "192.0.2.200" } });

const doc = (n: number): KevResponse => ({
  ok: true,
  updatedAt: "2026-10-12T14:00:00.000Z",
  catalogVersion: "2026.10.12",
  epssDate: "2026-10-12",
  entries: Array.from({ length: n }, (_, i) => ({
    cve: `CVE-2026-${1000 + i}`,
    vendor: "Fortinet",
    product: "FortiOS",
    name: "Heap overflow",
    added: "2026-10-10",
    description: "Remote code execution.",
    action: "Patch.",
    due: "2026-10-31",
    ransomware: false,
  })),
});

describe("GET /api/intel/kev", () => {
  it("says so plainly before the first data load", async () => {
    await env.VERDICTS.delete(KEV_KV_KEYS.recent);
    const res = await get("/api/intel/kev");
    expect(res.status).toBe(503);
    expect(((await res.json()) as ApiError).error).toBe("unavailable");
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("serves the recent list by default and the whole catalogue on request, cacheably", async () => {
    await env.VERDICTS.put(KEV_KV_KEYS.recent, JSON.stringify(doc(2)));
    await env.VERDICTS.put(KEV_KV_KEYS.all, JSON.stringify(doc(5)));

    const recent = await get("/api/intel/kev");
    expect(recent.status).toBe(200);
    expect(recent.headers.get("content-type")).toContain("application/json");
    expect(recent.headers.get("cache-control")).toBe("public, max-age=900");
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) expect(recent.headers.get(name)).toBe(value);
    expect(((await recent.json()) as KevResponse).entries).toHaveLength(2);

    const all = await get("/api/intel/kev?scope=all");
    expect(((await all.json()) as KevResponse).entries).toHaveLength(5);
  });

  it("serves the vendor list for the watchlist picker", async () => {
    await env.VERDICTS.put(KEV_KV_KEYS.vendors, JSON.stringify({ ok: true, updatedAt: "x", vendors: [{ vendor: "Fortinet", products: ["FortiOS"] }] }));
    const res = (await (await get("/api/intel/kev?scope=vendors")).json()) as { vendors: unknown[] };
    expect(res.vendors).toEqual([{ vendor: "Fortinet", products: ["FortiOS"] }]);
  });

  it("treats an unknown scope as recent", async () => {
    await env.VERDICTS.put(KEV_KV_KEYS.recent, JSON.stringify(doc(1)));
    expect(((await (await get("/api/intel/kev?scope=../../secrets")).json()) as KevResponse).entries).toHaveLength(1);
  });
});
