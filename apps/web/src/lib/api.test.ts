import { describe, expect, it, vi } from "vitest";
import type { LookupResponse } from "@bluebench/shared";
import { byoLookup, fetchKev, lookupReputation } from "./api";

const OK: LookupResponse = { ok: true, kind: "domain", value: "example.com", verdict: "not-listed", sources: [] };

/** Fake fetch that answers each call from a queue, recording what was asked. */
function fakeFetch(...responses: (Response | Error)[]) {
  return vi.fn(async (_path: string, _init?: RequestInit) => {
    const next = responses.shift();
    if (!next) throw new Error("no more responses");
    if (next instanceof Error) throw next;
    return next;
  });
}

describe("lookupReputation", () => {
  it("returns the result directly when a session already exists", async () => {
    const f = fakeFetch(Response.json(OK));
    const getToken = vi.fn();
    expect(await lookupReputation("domain", "example.com", getToken, f as unknown as typeof fetch)).toEqual(OK);
    expect(getToken).not.toHaveBeenCalled();
    expect(JSON.parse(f.mock.calls[0]![1]!.body as string)).toEqual({ kind: "domain", value: "example.com" });
  });

  it("runs the bot check on a challenge, creates a session and retries once", async () => {
    const f = fakeFetch(
      Response.json({ ok: false, error: "challenge", message: "", siteKey: "site-key" }, { status: 401 }),
      Response.json({ ok: true }),
      Response.json(OK),
    );
    const getToken = vi.fn(async () => "tok");
    expect(await lookupReputation("domain", "example.com", getToken, f as unknown as typeof fetch)).toEqual(OK);
    expect(getToken).toHaveBeenCalledWith("site-key");
    expect(f.mock.calls.map((c) => c[0])).toEqual(["/api/lookup", "/api/session", "/api/lookup"]);
    expect(JSON.parse(f.mock.calls[1]![1]!.body as string)).toEqual({ turnstileToken: "tok" });
  });

  it("explains when the bot check can't run", async () => {
    const f = fakeFetch(Response.json({ ok: false, error: "challenge", message: "", siteKey: "k" }, { status: 401 }));
    const res = await lookupReputation("domain", "example.com", async () => Promise.reject(new Error("blocked")), f as unknown as typeof fetch);
    expect(res).toMatchObject({ ok: false, error: "challenge" });
    expect(!res.ok && res.message).toContain("challenges.cloudflare.com");
  });

  it("passes limit messages through", async () => {
    const limit = { ok: false, error: "daily-limit", message: "You've used today's 100 free lookups." };
    const f = fakeFetch(Response.json(limit, { status: 429 }));
    expect(await lookupReputation("domain", "example.com", vi.fn(), f as unknown as typeof fetch)).toEqual(limit);
  });

  it("never shows a bare server error or network failure", async () => {
    const bare = await lookupReputation("domain", "x.com", vi.fn(), fakeFetch(Response.json({ ok: false, error: "Internal error" }, { status: 500 })) as unknown as typeof fetch);
    expect(!bare.ok && bare.message).toBe("Something went wrong on our side. Try again shortly.");
    const offline = await lookupReputation("domain", "x.com", vi.fn(), fakeFetch(new TypeError("offline")) as unknown as typeof fetch);
    expect(!offline.ok && offline.message).toContain("Check your connection");
  });
});

describe("byoLookup", () => {
  const KEY = "k".repeat(64);
  const otxAnswer = { pulse_info: { count: 2, pulses: [{ name: "Phishing kit" }] }, validation: [] };
  const relayAnswer = { ok: true, sources: [{ source: "virustotal", status: "not-listed", summary: "No vendor flags this as malicious (70 checked).", facts: [] }] };

  it("asks OTX directly without cookies, and the rest through the relay", async () => {
    const f = vi.fn(async (url: string, _init?: RequestInit) => (url.startsWith("https://otx") ? Response.json(otxAnswer) : Response.json(relayAnswer)));
    const res = await byoLookup("domain", "evil.example", { otx: KEY, virustotal: KEY, abuseipdb: KEY }, vi.fn(), f as unknown as typeof fetch);
    expect(res.map((r) => [r.source, r.status])).toEqual([
      ["virustotal", "not-listed"],
      ["otx", "listed"],
    ]);
    const otx = f.mock.calls.find((c) => c[0].startsWith("https://otx"))!;
    expect(otx[1]).toMatchObject({ credentials: "omit", referrerPolicy: "no-referrer", headers: { "X-OTX-API-KEY": KEY } });
    const relay = f.mock.calls.find((c) => c[0] === "/api/byo")!;
    // AbuseIPDB can't answer for a domain, so its key isn't sent anywhere.
    expect(JSON.parse(relay[1]!.body as string)).toEqual({ kind: "domain", value: "evil.example", keys: { virustotal: KEY } });
  });

  it("turns a relay failure into an error per source", async () => {
    const f = vi.fn(async () => Response.json({ ok: false, error: "rate-limited", message: "Wait a minute." }, { status: 429 }));
    const res = await byoLookup("ipv4", "185.220.101.7", { greynoise: KEY }, vi.fn(), f as unknown as typeof fetch);
    expect(res).toEqual([{ source: "greynoise", status: "error", summary: "Wait a minute.", facts: [] }]);
  });

  it("does nothing without keys", async () => {
    const f = vi.fn();
    expect(await byoLookup("md5", "0".repeat(32), {}, vi.fn(), f as unknown as typeof fetch)).toEqual([]);
    expect(f).not.toHaveBeenCalled();
  });
});

describe("fetchKev", () => {
  it("asks for the recent list by default and the whole catalogue on request, with no body", async () => {
    const f = vi.fn(async (_path: string, _init?: RequestInit) => Response.json({ ok: true, entries: [] }));
    await fetchKev("recent", f as unknown as typeof fetch);
    await fetchKev("all", f as unknown as typeof fetch);
    expect(f.mock.calls.map((c) => [c[0], c[1]!.method, c[1]!.body])).toEqual([
      ["/api/intel/kev", "GET", undefined],
      ["/api/intel/kev?scope=all", "GET", undefined],
    ]);
  });
});
