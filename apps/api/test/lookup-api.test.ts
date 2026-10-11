import { env, exports } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cacheKey, ipRateKey, SECURITY_HEADERS, type ApiError, type LookupResponse } from "@bluebench/shared";
import * as main from "../src/index.ts";
import { ANON_DAILY_LIMIT } from "../src/quota.ts";
import { hmac } from "../src/session.ts";
import { mockUpstream } from "./upstream.ts";

const BASE = "https://bluebench.dev";
let ipCounter = 1;
/** Each test gets its own client IP so per-IP rate limits don't leak between tests. */
const freshIp = () => `198.51.100.${ipCounter++}`;

function post(path: string, body: unknown, headers: Record<string, string> = {}) {
  return exports.default.fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

async function newSession(ip: string): Promise<string> {
  const res = await post("/api/session", { turnstileToken: "good-token" }, { "cf-connecting-ip": ip });
  expect(res.status).toBe(200);
  return res.headers.get("set-cookie")!.split(";")[0]!;
}

async function client() {
  const ip = freshIp();
  const cookie = await newSession(ip);
  return {
    ip,
    cookie,
    lookup: (kind: string, value: string) => post("/api/lookup", { kind, value }, { cookie, "cf-connecting-ip": ip }),
  };
}

/** KV writes happen in waitUntil; wait for the entry to land. */
async function cached(kind: "domain" | "url" | "sha256", value: string) {
  const key = await cacheKey(kind, value);
  return vi.waitFor(async () => {
    const raw = await env.VERDICTS.get(key);
    if (!raw) throw new Error("not cached yet");
    return raw;
  });
}

afterEach(() => vi.restoreAllMocks());

describe("main module", () => {
  it("exports only handlers and classes (workerd rejects anything else at startup)", () => {
    for (const [name, value] of Object.entries(main)) {
      expect(typeof value === "function" || typeof (value as { fetch?: unknown }).fetch === "function", name).toBe(true);
    }
  });
});

describe("POST /api/session", () => {
  it("sets a hardened session cookie for a valid Turnstile token", async () => {
    mockUpstream();
    const res = await post("/api/session", { turnstileToken: "good-token" }, { "cf-connecting-ip": freshIp() });
    expect(res.status).toBe(200);
    const cookie = res.headers.get("set-cookie")!;
    expect(cookie).toMatch(/^__Host-bb_session=[\w-]+\.\d+\.[\w-]+;/);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("SameSite=Strict");
    expect(cookie).toContain("Path=/");
    expect(cookie).toContain("Max-Age=86400");
  });

  it("asks for another challenge when Turnstile says no", async () => {
    mockUpstream();
    const res = await post("/api/session", { turnstileToken: "bot" }, { "cf-connecting-ip": freshIp() });
    expect(res.status).toBe(401);
    const body = (await res.json()) as ApiError;
    expect(body.error).toBe("challenge");
    expect(res.headers.get("set-cookie")).toBeNull();
  });
});

describe("POST /api/lookup", () => {
  it("demands a Turnstile challenge without a session, and says which site key to use", async () => {
    const res = await post("/api/lookup", { kind: "domain", value: "example.com" });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ ok: false, error: "challenge", siteKey: "1x00000000000000000000AA" });
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) expect(res.headers.get(name), name).toBe(value);
  });

  it("rejects a forged session cookie", async () => {
    const res = await post("/api/lookup", { kind: "domain", value: "example.com" }, {
      cookie: "__Host-bb_session=AAAAAAAAAAAAAAAAAAAAAA.9999999999.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    expect(res.status).toBe(401);
  });

  it("merges sources into a verdict and caches abuse.ch answers, never the raw indicator", async () => {
    const calls = mockUpstream({
      urlhausHost: {
        "bad.example": {
          url_count: 3,
          firstseen: "2026-09-01 10:00:00 UTC",
          urls: [{ url_status: "online" }, { url_status: "offline" }],
          blacklists: { spamhaus_dbl: "not listed", surbl: "not listed" },
          urlhaus_reference: "https://urlhaus.abuse.ch/host/bad.example/",
        },
      },
    });
    const c = await client();
    const res = await c.lookup("domain", "BAD[.]example");
    expect(res.status).toBe(200);
    const body = (await res.json()) as LookupResponse;
    expect(body.value).toBe("bad.example");
    expect(body.verdict).toBe("listed");
    const bySource = Object.fromEntries(body.sources.map((s) => [s.source, s]));
    expect(bySource.urlhaus).toMatchObject({
      status: "listed",
      summary: "Hosted 3 known malware URLs, 1 still online.",
      link: "https://urlhaus.abuse.ch/host/bad.example/",
    });
    expect(bySource.threatfox!.status).toBe("not-listed");
    expect(bySource.safebrowsing!.status).toBe("not-listed");

    const raw = await cached("domain", "bad.example");
    expect(raw).not.toContain("bad.example");
    expect(Object.keys(JSON.parse(raw)).sort()).toEqual(["threatfox", "urlhaus"]); // SB non-match isn't cached

    // Second lookup: abuse.ch from cache, Safe Browsing asked again.
    calls.length = 0;
    const again = (await (await c.lookup("domain", "bad.example")).json()) as LookupResponse;
    expect(again.sources.find((s) => s.source === "urlhaus")).toMatchObject({
      cached: true,
      link: "https://urlhaus.abuse.ch/host/bad.example/", // restored from the placeholder
    });
    expect(calls.map((x) => x.host)).toEqual(["safebrowsing.googleapis.com"]);
  });

  it("hedges Safe Browsing wording and caches a match only for its cache duration", async () => {
    mockUpstream({
      safeBrowsing: {
        "https://phish.example/login": [{ threatType: "SOCIAL_ENGINEERING", cacheDuration: "300s" }],
      },
    });
    const c = await client();
    const body = (await (await c.lookup("url", "https://phish.example/login")).json()) as LookupResponse;
    const sb = body.sources.find((s) => s.source === "safebrowsing")!;
    expect(sb.status).toBe("listed");
    expect(sb.summary).toBe("Suspected phishing or deceptive site. Advisory provided by Google.");
    const entry = JSON.parse(await cached("url", "https://phish.example/login"));
    const ttl = entry.safebrowsing.freshUntil - Date.parse(sb.checkedAt!);
    expect(ttl).toBe(300_000);
    expect(entry.safebrowsing.staleUntil).toBe(entry.safebrowsing.freshUntil); // never served stale
  });

  it("reports an upstream failure per source, not as a bare error", async () => {
    mockUpstream({ down: ["threatfox-api.abuse.ch"] });
    const c = await client();
    const body = (await (await c.lookup("domain", "flaky.example")).json()) as LookupResponse;
    expect(body.verdict).toBe("incomplete");
    expect(body.sources.find((s) => s.source === "threatfox")).toMatchObject({
      status: "error",
      summary: "Couldn't reach ThreatFox. Try again shortly.",
    });
  });

  it.each([
    [{ kind: "ipv4", value: "10.0.0.1" }, 400],
    [{ kind: "ipv4", value: "127.0.0.1" }, 400],
    [{ kind: "jwt", value: "a.b.c" }, 400],
    [{ kind: "sha256", value: "example.com" }, 400],
    [{ kind: "domain" }, 400],
  ])("rejects %j", async (body, status) => {
    mockUpstream();
    const c = await client();
    const res = await post("/api/lookup", body, { cookie: c.cookie, "cf-connecting-ip": c.ip });
    expect(res.status).toBe(status);
    expect(((await res.json()) as ApiError).error).toBe("invalid");
  });

  it("refuses non-JSON bodies and oversized requests", async () => {
    mockUpstream();
    const c = await client();
    const h = { cookie: c.cookie, "cf-connecting-ip": c.ip };
    expect((await post("/api/lookup", "kind=domain", { ...h, "content-type": "application/x-www-form-urlencoded" })).status).toBe(415);
    expect((await post("/api/lookup", "x".repeat(70_000), h)).status).toBe(413);
  });

  it("refuses cross-site requests", async () => {
    mockUpstream();
    const c = await client();
    const res = await post("/api/lookup", { kind: "domain", value: "example.com" }, {
      cookie: c.cookie,
      "cf-connecting-ip": c.ip,
      origin: "https://evil.example",
    });
    expect(res.status).toBe(403);
  });

  it("rate-limits a session to 10 lookups a minute", async () => {
    mockUpstream();
    const c = await client();
    for (let i = 0; i < 10; i++) expect((await c.lookup("domain", "example.com")).status).toBe(200);
    const res = await c.lookup("domain", "example.com");
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("60");
    expect(((await res.json()) as ApiError).error).toBe("rate-limited");
  });

  it("stops at the daily cap for an IP group, even with a fresh session", async () => {
    mockUpstream();
    const c = await client();
    const ipKey = await hmac("test-session-secret", `ip:${ipRateKey(c.ip)}`);
    const day = new Date().toISOString().slice(0, 10);
    await runInDurableObject(env.USAGE.get(env.USAGE.idFromName("daily")), (_o, state) => {
      state.storage.sql.exec("INSERT INTO usage (day, key, n) VALUES (?, ?, ?)", day, ipKey, ANON_DAILY_LIMIT);
    });
    const res = await c.lookup("domain", "example.com");
    expect(res.status).toBe(429);
    const body = (await res.json()) as ApiError;
    expect(body.error).toBe("daily-limit");
    expect(body.message).toContain("100 free lookups");
  });
});
