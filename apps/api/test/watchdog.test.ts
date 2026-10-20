import { env, exports } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { KEV_KV_KEYS, type StatusResponse } from "@bluebench/shared";
import { eq } from "drizzle-orm";
import { db } from "../src/auth.ts";
import { alert, healthCheck, intelState, user } from "../src/db/schema.ts";
import { tick } from "../src/monitor/run.ts";
import { KNOWN_BAD_SHA256, runWatchdog, WATCHDOG_PARTS } from "../src/monitor/watchdog.ts";
import { freshEmail } from "./account.ts";
import { mockUpstream, type UpstreamFixtures } from "./upstream.ts";

const d = () => db(env);
const NOW = Date.parse("2026-10-13T14:45:00Z");
const HOUR = 3600_000;
const openQuota = { idFromName: () => ({}), get: () => ({ acquire: async () => ({ ok: true }) }) } as unknown as typeof env.PROVIDER_QUOTA;
const OWNER = freshEmail();
const watchEnv = { ...env, PROVIDER_QUOTA: openQuota, OWNER_EMAIL: OWNER };

const BAZAAR_HIT = { sha256_hash: KNOWN_BAD_SHA256, signature: "WannaCry", file_type: "exe", first_seen: "2017-05-12 00:00:00" };
const cert = { issuer_name: "C=US, O=Let's Encrypt, CN=R11", name_value: "bluebench.dev", not_before: "2026-10-01T00:00:00", not_after: "2026-12-30T00:00:00" };

/** abuse.ch and Safe Browsing from the shared mock, plus crt.sh (answers with `crtsh`, or a status code). */
function mockAll(f: UpstreamFixtures = {}, crtsh: object[] | number = [cert]) {
  mockUpstream({ bazaar: { [KNOWN_BAD_SHA256]: BAZAAR_HIT }, ...f });
  const real = vi.mocked(fetch).getMockImplementation()!;
  vi.mocked(fetch).mockImplementation(async (input, init) => {
    const url = new URL(new Request(input, init).url);
    if (url.hostname === "crt.sh") return typeof crtsh === "number" ? new Response("busy", { status: crtsh }) : Response.json(crtsh);
    if (url.hostname === "api.certspotter.com") return Response.json([]);
    return real(input, init);
  });
}

const freshIntel = (now = NOW) => env.VERDICTS.put(KEV_KV_KEYS.recent, JSON.stringify({ ok: true, updatedAt: new Date(now - 2 * HOUR).toISOString(), catalogVersion: "x", epssDate: null, entries: [] }));
const ownerAlerts = async () => {
  const [u] = await d().select().from(user).where(eq(user.email, OWNER));
  return u ? d().select().from(alert).where(eq(alert.userId, u.id)) : [];
};

beforeEach(async () => {
  await d().delete(healthCheck);
  await freshIntel();
  if (!(await d().select().from(user).where(eq(user.email, OWNER))).length) {
    const t = new Date(NOW);
    await d().insert(user).values({ id: crypto.randomUUID(), name: "", email: OWNER, emailVerified: true, createdAt: t, updatedAt: t });
  }
});
afterEach(() => vi.restoreAllMocks());

describe("runWatchdog", () => {
  it("passes when every service answers as expected", async () => {
    mockAll();
    const rows = await runWatchdog(watchEnv, d(), NOW);
    expect(Object.fromEntries(rows.map((r) => [r.id, r.ok]))).toEqual({
      urlhaus: true,
      threatfox: true,
      malwarebazaar: true,
      safebrowsing: true,
      intel: true,
      certificates: true,
    });
  });

  it("alerts the owner after two failed runs in a row, once, then announces the recovery", async () => {
    mockAll({ down: ["threatfox-api.abuse.ch"] });
    await runWatchdog(watchEnv, d(), NOW);
    expect(await ownerAlerts()).toEqual([]); // one failure isn't worth a notification

    await runWatchdog(watchEnv, d(), NOW + HOUR);
    const [first, ...rest] = await ownerAlerts();
    expect(rest).toEqual([]);
    expect(first).toMatchObject({ kind: "health", title: "Bluebench: a check is failing" });
    expect(first!.body).toContain("ThreatFox has been failing since 2026-10-13 14:45 UTC");

    await runWatchdog(watchEnv, d(), NOW + 2 * HOUR);
    expect(await ownerAlerts()).toHaveLength(1); // still failing: no repeat

    vi.restoreAllMocks();
    mockAll();
    await runWatchdog(watchEnv, d(), NOW + 3 * HOUR);
    const all = await ownerAlerts();
    expect(all).toHaveLength(2);
    expect(all.find((a) => a.title === "Bluebench: all clear again")!.body).toContain("ThreatFox is working again");
  });

  it("spreads the checks over minutes 45–47 of tick, and sends one alert from the last part", async () => {
    mockAll({ down: ["threatfox-api.abuse.ch"] }, 502); // ThreatFox (part 0) and certificates (part 2) fail
    const hour = async (start: number) => {
      await d().update(alert).set({ deliveredAt: new Date(start) }); // delivery would take the run otherwise
      for (let m = 0; m < WATCHDOG_PARTS; m++) expect(await tick(watchEnv, { now: start + m * 60_000, waitUntil: () => {} })).toBe("watchdog");
    };
    await d().insert(intelState).values({ key: "housekeeping_at", value: String(NOW + 9 * HOUR) }).onConflictDoUpdate({ target: intelState.key, set: { value: String(NOW + 9 * HOUR) } });
    await d().delete(alert); // earlier tests' alerts would count here, and tick would stop to deliver them

    expect(WATCHDOG_PARTS).toBe(3);
    const part0 = await runWatchdog(watchEnv, d(), NOW, 0);
    expect(part0.map((r) => r.id).sort()).toEqual(["safebrowsing", "threatfox", "urlhaus"]);
    await d().delete(healthCheck);

    await hour(NOW);
    expect(await ownerAlerts()).toEqual([]);
    await hour(NOW + HOUR);
    const alerts = await ownerAlerts();
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.body).toContain("ThreatFox has been failing");
    expect(alerts[0]!.body).toContain("Certificate Transparency search has been failing");

    vi.restoreAllMocks();
    mockAll();
    await hour(NOW + 2 * HOUR);
    const after = await ownerAlerts();
    expect(after).toHaveLength(2);
    const clear = after.find((a) => a.title === "Bluebench: all clear again")!;
    expect(clear.body).toContain("ThreatFox is working again (it had been failing since 2026-10-13 14:45 UTC)");
    expect(clear.body).toContain("Certificate Transparency search is working again");
    expect((await d().select().from(healthCheck)).every((r) => r.ok && !r.alerted && r.failingSince === null)).toBe(true);
  });

  it("fails MalwareBazaar if the known sample stops being listed (catches broken parsing, not just outages)", async () => {
    mockAll({ bazaar: {} });
    const rows = await runWatchdog(watchEnv, d(), NOW);
    expect(rows.find((r) => r.id === "malwarebazaar")).toMatchObject({ ok: false, detail: expect.stringContaining("expected the WannaCry sample to be listed") });
  });

  it("fails the intel check when the data job hasn't run for over 36 hours", async () => {
    mockAll();
    await freshIntel(NOW - 40 * HOUR);
    const rows = await runWatchdog(watchEnv, d(), NOW);
    expect(rows.find((r) => r.id === "intel")).toMatchObject({ ok: false, detail: "last updated 42 h ago" });
  });

  it("fails certificates only when crt.sh and Cert Spotter both have nothing", async () => {
    mockAll({}, 502);
    const rows = await runWatchdog(watchEnv, d(), NOW);
    expect(rows.find((r) => r.id === "certificates")).toMatchObject({ ok: false, detail: expect.stringContaining("crt.sh") });
  });

  it("marks unconfigured sources off instead of failing", async () => {
    mockAll();
    const rows = await runWatchdog({ ...watchEnv, SAFE_BROWSING_API_KEY: undefined }, d(), NOW);
    expect(rows.find((r) => r.id === "safebrowsing")).toMatchObject({ ok: true, detail: "off" });
  });
});

describe("GET /api/status", () => {
  it("shows each check's state, without details", async () => {
    mockAll({ down: ["urlhaus-api.abuse.ch"] });
    await runWatchdog(watchEnv, d(), NOW);
    vi.restoreAllMocks();
    const res = await exports.default.fetch("https://bluebench.dev/api/status", { headers: { "cf-connecting-ip": "192.0.2.77" } });
    expect(res.headers.get("cache-control")).toBe("public, max-age=300");
    const body = (await res.json()) as StatusResponse;
    expect(body.checkedAt).toBe(new Date(NOW).toISOString());
    expect(body.checks.find((c) => c.id === "urlhaus")).toEqual({ id: "urlhaus", label: "URLhaus", state: "failing", since: new Date(NOW).toISOString() });
    expect(body.checks.find((c) => c.id === "threatfox")!.state).toBe("ok");
    expect(JSON.stringify(body)).not.toContain("HTTP 500");
  });
});
