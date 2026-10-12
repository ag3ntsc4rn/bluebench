import { exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ApiError, ByoResponse } from "@bluebench/shared";

const BASE = "https://bluebench.dev";
const VT_KEY = "v".repeat(64);
const AB_KEY = "b".repeat(80);
const GN_KEY = "g".repeat(32);
let ipCounter = 1;
const freshIp = () => `192.0.2.${ipCounter++}`;

function post(path: string, body: unknown, headers: Record<string, string> = {}) {
  return exports.default.fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

/** Fake Turnstile and providers. Returns the outbound requests (URL + headers). */
function mockProviders(answers: Partial<Record<string, { status: number; body?: unknown }>> = {}) {
  const calls: { url: string; headers: Headers; redirect: Request["redirect"] }[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const req = new Request(input, init);
    const url = new URL(req.url);
    if (url.hostname === "challenges.cloudflare.com") return Response.json({ success: true });
    calls.push({ url: url.href, headers: req.headers, redirect: req.redirect });
    const a = answers[url.hostname] ?? { status: 404, body: {} };
    return Response.json(a.body ?? {}, { status: a.status });
  });
  return calls;
}

async function client() {
  const ip = freshIp();
  const res = await post("/api/session", { turnstileToken: "good-token" }, { "cf-connecting-ip": ip });
  const cookie = res.headers.get("set-cookie")!.split(";")[0]!;
  return (body: unknown) => post("/api/byo", body, { cookie, "cf-connecting-ip": ip });
}

afterEach(() => vi.restoreAllMocks());

describe("POST /api/byo", () => {
  it("needs a session", async () => {
    mockProviders();
    const res = await post("/api/byo", { kind: "ipv4", value: "185.220.101.7", keys: { virustotal: VT_KEY } }, { "cf-connecting-ip": freshIp() });
    expect(res.status).toBe(401);
    expect(((await res.json()) as ApiError).error).toBe("challenge");
  });

  it("relays to each provider with the user's key and parses the answers", async () => {
    const calls = mockProviders({
      "www.virustotal.com": { status: 200, body: { data: { id: "185.220.101.7", attributes: { last_analysis_stats: { malicious: 5, suspicious: 0, harmless: 70, undetected: 0 } } } } },
      "api.abuseipdb.com": { status: 200, body: { data: { abuseConfidenceScore: 0, totalReports: 0 } } },
      "api.greynoise.io": { status: 401, body: { message: "bad key" } },
    });
    const byo = await client();
    const res = await byo({ kind: "ipv4", value: "185.220.101.7", keys: { virustotal: VT_KEY, abuseipdb: AB_KEY, greynoise: GN_KEY } });
    expect(res.status).toBe(200);
    const body = (await res.json()) as ByoResponse;
    expect(body.sources.map((s) => [s.source, s.status])).toEqual([
      ["virustotal", "listed"],
      ["abuseipdb", "not-listed"],
      ["greynoise", "error"],
    ]);

    expect(calls.map((c) => new URL(c.url).hostname).sort()).toEqual(["api.abuseipdb.com", "api.greynoise.io", "www.virustotal.com"]);
    const vt = calls.find((c) => c.url.includes("virustotal"))!;
    expect(vt.headers.get("x-apikey")).toBe(VT_KEY);
    expect(vt.redirect).toBe("manual");
    expect(calls.find((c) => c.url.includes("abuseipdb"))!.headers.get("key")).toBe(AB_KEY);
    // Nobody else gets the keys or our cookies.
    for (const c of calls) expect(c.headers.get("cookie")).toBeNull();
  });

  it("only asks providers that can answer the kind", async () => {
    const calls = mockProviders();
    const byo = await client();
    const res = await byo({ kind: "domain", value: "example.com", keys: { virustotal: VT_KEY, abuseipdb: AB_KEY, greynoise: GN_KEY } });
    expect(((await res.json()) as ByoResponse).sources.map((s) => s.source)).toEqual(["virustotal"]);
    expect(calls).toHaveLength(1);
  });

  it("refuses OTX keys, odd keys and private addresses", async () => {
    const calls = mockProviders();
    const byo = await client();
    expect((await byo({ kind: "ipv4", value: "185.220.101.7", keys: { otx: VT_KEY } })).status).toBe(400);
    expect((await byo({ kind: "ipv4", value: "185.220.101.7", keys: { virustotal: "short" } })).status).toBe(400);
    expect((await byo({ kind: "ipv4", value: "10.0.0.1", keys: { virustotal: VT_KEY } })).status).toBe(400);
    expect(calls).toHaveLength(0);
  });

  it("reports an unreachable provider without failing the rest", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = new URL(new Request(input, init).url);
      if (url.hostname === "challenges.cloudflare.com") return Response.json({ success: true });
      if (url.hostname === "api.abuseipdb.com") throw new TypeError("connection reset");
      return Response.json({ data: { attributes: { last_analysis_stats: { malicious: 0, harmless: 10 } } } });
    });
    const byo = await client();
    const body = (await (await byo({ kind: "ipv4", value: "185.220.101.7", keys: { virustotal: VT_KEY, abuseipdb: AB_KEY } })).json()) as ByoResponse;
    expect(body.sources.map((s) => s.status)).toEqual(["not-listed", "error"]);
  });
});
