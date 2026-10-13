import { env, exports } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ipRateKey, type ApiError, type BatchItemError, type BatchLookupResponse, type LookupResponse } from "@bluebench/shared";
import { ANON_DAILY_LIMIT } from "../src/quota.ts";
import { hmac } from "../src/session.ts";
import { mockUpstream } from "./upstream.ts";

const BASE = "https://bluebench.dev";
let ipCounter = 1;
const freshIp = () => `198.18.0.${ipCounter++}`;

function post(path: string, body: unknown, headers: Record<string, string> = {}) {
  return exports.default.fetch(`${BASE}${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
}

async function client() {
  const ip = freshIp();
  const res = await post("/api/session", { turnstileToken: "good-token" }, { "cf-connecting-ip": ip });
  const cookie = res.headers.get("set-cookie")!.split(";")[0]!;
  return { ip, batch: (items: { kind: string; value: string }[]) => post("/api/lookup/batch", { items }, { cookie, "cf-connecting-ip": ip }) };
}

async function setUsed(ip: string, n: number) {
  const ipKey = await hmac("test-session-secret", `ip:${ipRateKey(ip)}`);
  const day = new Date().toISOString().slice(0, 10);
  await runInDurableObject(env.USAGE.get(env.USAGE.idFromName("daily")), (_o, state) => {
    state.storage.sql.exec("INSERT INTO usage (day, key, n) VALUES (?, ?, ?)", day, ipKey, n);
  });
}

afterEach(() => vi.restoreAllMocks());

describe("POST /api/lookup/batch", () => {
  it("needs a session", async () => {
    const res = await post("/api/lookup/batch", { items: [{ kind: "domain", value: "example.com" }] }, { "cf-connecting-ip": freshIp() });
    expect(res.status).toBe(401);
  });

  it("looks up each indicator in order, refusing what can't be looked up, within the subrequest budget", async () => {
    const calls = mockUpstream({ urlhausHost: { "bad.example": { url_count: 1, urls: [], blacklists: {} } } });
    const c = await client();
    calls.length = 0;
    const res = await c.batch([
      { kind: "domain", value: "bad[.]example" },
      { kind: "ipv4", value: "10.0.0.1" }, // private: nobody has reputation for it
      { kind: "domain", value: "batch-a.example" },
      { kind: "domain", value: "batch-b.example" },
      { kind: "domain", value: "batch-c.example" },
    ]);
    expect(res.status).toBe(200);
    const { results } = (await res.json()) as BatchLookupResponse;
    expect(results.map((r) => (r.ok ? `${r.value}:${r.verdict}` : `${r.value}:${r.error}`))).toEqual([
      "bad.example:listed",
      "10.0.0.1:invalid",
      "batch-a.example:not-listed",
      "batch-b.example:not-listed",
      "batch-c.example:not-listed",
    ]);
    // 4 domains × 3 sources; with cache reads and quota permits the Worker stays well inside 50 subrequests.
    expect(calls.length).toBeLessThanOrEqual(12);
  });

  it("refuses more than five at once", async () => {
    mockUpstream();
    const c = await client();
    const six = Array.from({ length: 6 }, (_, i) => ({ kind: "domain", value: `six${i}.example` }));
    expect((await c.batch(six)).status).toBe(400);
  });

  it("checks as many as today's cap allows and marks the rest", async () => {
    mockUpstream();
    const c = await client();
    await setUsed(c.ip, ANON_DAILY_LIMIT - 2);
    const res = await c.batch(["cap-a", "cap-b", "cap-c"].map((d) => ({ kind: "domain", value: `${d}.example` })));
    const { results } = (await res.json()) as BatchLookupResponse;
    expect(results.map((r) => r.ok)).toEqual([true, true, false]);
    expect((results[2] as BatchItemError).error).toBe("daily-limit");
    expect((results[0] as LookupResponse).verdict).toBe("not-listed");
  });

  it("says so plainly when nothing is left today", async () => {
    mockUpstream();
    const c = await client();
    await setUsed(c.ip, ANON_DAILY_LIMIT);
    const res = await c.batch([{ kind: "domain", value: "none-left.example" }]);
    expect(res.status).toBe(429);
    expect(((await res.json()) as ApiError).error).toBe("daily-limit");
  });
});
