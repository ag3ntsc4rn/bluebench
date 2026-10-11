import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { LookupKind } from "@bluebench/shared";
import type { Env } from "../src/env.ts";
import { lookup } from "../src/lookup.ts";
import type { QuotaDenial } from "../src/quota.ts";
import { mockUpstream } from "./upstream.ts";

const HOUR = 3600_000;
let n = 0;
/** A unique domain per test, so KV entries and coalescing don't leak between tests. */
const domain = () => `t${n++}-${Date.now()}.example`;

/** Run a lookup and wait for its cache write. */
async function run(kind: LookupKind, value: string, opts: { env?: Partial<Env>; now?: number; deny?: QuotaDenial } = {}) {
  const pending: Promise<unknown>[] = [];
  const e: Env = { ...env, ...opts.env };
  if (opts.deny) {
    const reason = opts.deny;
    e.PROVIDER_QUOTA = {
      idFromName: () => ({}),
      get: () => ({ acquire: async () => ({ ok: false, reason }) }),
    } as unknown as Env["PROVIDER_QUOTA"];
  }
  const res = await lookup(kind, value, { env: e, tier: "anon", waitUntil: (p) => pending.push(p), now: () => opts.now ?? Date.now() });
  await Promise.all(pending);
  return res;
}

const source = (res: Awaited<ReturnType<typeof run>>, id: string) => res.sources.find((s) => s.source === id)!;

afterEach(() => vi.restoreAllMocks());

describe("lookup", () => {
  it("skips a source whose key isn't configured, and says so", async () => {
    mockUpstream({});
    const res = await run("domain", domain(), { env: { SAFE_BROWSING_API_KEY: undefined } });
    expect(source(res, "safebrowsing")).toMatchObject({ status: "skipped", summary: "Not switched on for this server yet." });
    expect(res.verdict).toBe("incomplete");
  });

  it("serves a stale abuse.ch answer when the budget is spent, and lists Safe Browsing as skipped", async () => {
    const d = domain();
    mockUpstream({ urlhausHost: { [d]: { url_count: 1, urls: [], blacklists: {} } } });
    const t0 = Date.now();
    await run("domain", d, { now: t0 });

    const later = await run("domain", d, { now: t0 + 7 * HOUR, deny: "daily" }); // past fresh (6 h), within stale (24 h)
    expect(source(later, "urlhaus")).toMatchObject({ status: "listed", cached: true, stale: true });
    expect(source(later, "safebrowsing")).toMatchObject({ status: "skipped" });
    expect(source(later, "safebrowsing").summary).toContain("budget");
    expect(later.verdict).toBe("listed");
  });

  it("doesn't serve abuse.ch answers older than 24 hours", async () => {
    const d = domain();
    mockUpstream({ urlhausHost: { [d]: { url_count: 1, urls: [], blacklists: {} } } });
    const t0 = Date.now();
    await run("domain", d, { now: t0 });
    const res = await run("domain", d, { now: t0 + 25 * HOUR, deny: "daily" });
    expect(source(res, "urlhaus").status).toBe("skipped");
  });

  it("never serves a Safe Browsing match past its cache duration, even when the budget is spent", async () => {
    const url = `https://${domain()}/`;
    mockUpstream({ safeBrowsing: { [url]: [{ threatType: "MALWARE", cacheDuration: "300s" }] } });
    const t0 = Date.now();
    expect(source(await run("url", url, { now: t0 }), "safebrowsing").status).toBe("listed");
    expect(source(await run("url", url, { now: t0 + 299_000, deny: "daily" }), "safebrowsing")).toMatchObject({ status: "listed", cached: true });
    expect(source(await run("url", url, { now: t0 + 301_000, deny: "daily" }), "safebrowsing").status).toBe("skipped");
  });

  it("falls back to a stale answer when the upstream call fails", async () => {
    const d = domain();
    mockUpstream({ urlhausHost: { [d]: { url_count: 2, urls: [], blacklists: {} } } });
    const t0 = Date.now();
    await run("domain", d, { now: t0 });
    vi.restoreAllMocks();
    mockUpstream({ down: ["urlhaus-api.abuse.ch"] });
    expect(source(await run("domain", d, { now: t0 + 7 * HOUR }), "urlhaus")).toMatchObject({ status: "listed", stale: true });
  });

  it("coalesces concurrent lookups of the same indicator", async () => {
    const calls = mockUpstream({});
    const d = domain();
    const deps = { env, tier: "anon" as const, waitUntil: () => {} };
    const [a, b] = await Promise.all([lookup("domain", d, deps), lookup("domain", d, deps)]);
    expect(a).toBe(b);
    expect(calls.filter((c) => c.host === "urlhaus-api.abuse.ch")).toHaveLength(1);
  });
});

describe("providers", () => {
  it("ThreatFox: matches an IP stored as ip:port, but not a longer IP", async () => {
    mockUpstream({
      threatfox: {
        "203.0.113.9": [
          { id: 1, ioc: "203.0.113.90:443", threat_type_desc: "Botnet C2", malware_printable: "Wrong" },
          { id: 2, ioc: "203.0.113.9:8080", threat_type_desc: "Botnet C2", malware_printable: "Cobalt Strike", confidence_level: 100 },
        ],
      },
    });
    // lookup() trusts its caller; the route rejects documentation ranges like this one before getting here.
    const tf = source(await run("ipv4", "203.0.113.9"), "threatfox");
    expect(tf).toMatchObject({ status: "listed", summary: "Listed as Botnet C2 (Cobalt Strike).", link: "https://threatfox.abuse.ch/ioc/2/" });
    expect(tf.facts).toContainEqual({ label: "Confidence", value: "100%" });
  });

  it("MalwareBazaar: summarises a known sample with a link", async () => {
    const sha = "a".repeat(64);
    mockUpstream({ bazaar: { [sha]: { sha256_hash: sha, signature: "AgentTesla", file_type: "exe", first_seen: "2026-01-02 03:04:05" } } });
    const mb = source(await run("sha256", sha), "malwarebazaar");
    expect(mb).toMatchObject({ status: "listed", summary: "Known malware sample (AgentTesla).", link: `https://bazaar.abuse.ch/sample/${sha}/` });
    expect(mb.facts).toContainEqual({ label: "First seen", value: "2026-01-02" });
  });

  it("URLhaus: reports a listed URL and whether it's online", async () => {
    const url = `http://${domain()}/x.exe`;
    mockUpstream({ urlhausUrl: { [url]: { url_status: "online", threat: "malware_download", tags: ["exe"], urlhaus_reference: "https://urlhaus.abuse.ch/url/42/" } } });
    expect(source(await run("url", url), "urlhaus")).toMatchObject({
      status: "listed",
      summary: "Listed as a malware distribution URL, still online.",
    });
  });

  it("treats a bad auth key as an error, not as 'not listed'", async () => {
    mockUpstream({});
    const res = await run("domain", domain(), { env: { ABUSECH_AUTH_KEY: "wrong" } });
    expect(source(res, "urlhaus").status).toBe("error");
  });
});
