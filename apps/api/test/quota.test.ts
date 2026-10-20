import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { ANON_SHARE, PROVIDER_LIMITS, type ProviderQuota } from "../src/quota.ts";

function seedDay(q: DurableObjectStub<ProviderQuota>, day: string, total: number, anon: number) {
  return runInDurableObject(q, (_o, state) => {
    state.storage.sql.exec("INSERT INTO daily (day, total, anon) VALUES (?, ?, ?)", day, total, anon);
  });
}

const quota = () => env.PROVIDER_QUOTA.get(env.PROVIDER_QUOTA.newUniqueId());
const usage = () => env.USAGE.get(env.USAGE.newUniqueId());

const DAY1 = Date.parse("2026-10-11T12:00:00Z");
const MIN = 60_000;

describe("ProviderQuota", () => {
  it("allows a burst up to the per-minute rate, then refills", async () => {
    const q = quota();
    const { perMinute } = PROVIDER_LIMITS.urlhaus;
    for (let i = 0; i < perMinute; i++) expect(await q.acquire("urlhaus", "user", DAY1)).toEqual({ ok: true });
    expect(await q.acquire("urlhaus", "user", DAY1)).toEqual({ ok: false, reason: "rate" });
    // One token back after 1/perMinute of a minute.
    expect(await q.acquire("urlhaus", "user", DAY1 + Math.ceil(MIN / perMinute))).toEqual({ ok: true });
  });

  it("grants several calls at once, all or nothing, within the burst (Cert Spotter's pages)", async () => {
    const q = quota();
    const { perMinute, burst } = PROVIDER_LIMITS.certspotter;
    expect(burst).toBe(4);
    expect(perMinute * 60).toBeLessThanOrEqual(100); // the free plan's hourly limit
    expect(await q.acquire("certspotter", "user", DAY1, 2)).toEqual({ ok: true });
    expect(await q.acquire("certspotter", "user", DAY1, 2)).toEqual({ ok: true });
    expect(await q.acquire("certspotter", "user", DAY1, 1)).toEqual({ ok: false, reason: "rate" });
    // 1.5 a minute: two calls back after 80 seconds.
    expect(await q.acquire("certspotter", "user", DAY1 + 80_000, 2)).toEqual({ ok: true });
    const [row] = await runInDurableObject(q, (_o, state) => state.storage.sql.exec("SELECT total FROM daily").toArray());
    expect(row).toEqual({ total: 6 });
  });

  it("caps anonymous traffic at its share of the daily budget, leaving the rest for signed-in users", async () => {
    const q = quota();
    const anonCap = Math.floor(PROVIDER_LIMITS.threatfox.perDay * ANON_SHARE);
    await seedDay(q, "2026-10-11", anonCap - 1, anonCap - 1);
    expect(await q.acquire("threatfox", "anon", DAY1)).toEqual({ ok: true });
    expect(await q.acquire("threatfox", "anon", DAY1)).toEqual({ ok: false, reason: "daily" });
    expect(await q.acquire("threatfox", "user", DAY1)).toEqual({ ok: true });
  });

  it("leaves room in KV's 1,000 writes a day for the Intel workflow", () => {
    expect(PROVIDER_LIMITS["kv-writes"].perDay).toBeLessThanOrEqual(1000 - 50);
  });

  it("stops everyone at the daily budget and resets the next UTC day", async () => {
    const q = quota();
    const { perDay } = PROVIDER_LIMITS.malwarebazaar;
    await seedDay(q, "2026-10-11", perDay - 1, 0);
    expect(await q.acquire("malwarebazaar", "user", DAY1)).toEqual({ ok: true });
    expect(await q.acquire("malwarebazaar", "user", DAY1)).toEqual({ ok: false, reason: "daily" });
    expect(await q.acquire("malwarebazaar", "user", Date.parse("2026-10-12T00:00:01Z"))).toEqual({ ok: true });
    // The new day's first call drops yesterday's row.
    const days = await runInDurableObject(q, (_o, state) => state.storage.sql.exec("SELECT day FROM daily").toArray());
    expect(days).toEqual([{ day: "2026-10-12" }]);
  });
});

describe("UsageCounter", () => {
  it("counts per key and refuses at the limit", async () => {
    const u = usage();
    for (let i = 1; i <= 3; i++) expect(await u.consume(["tok", "ip"], 3, DAY1)).toEqual({ ok: true, used: i });
    expect(await u.consume(["tok", "ip"], 3, DAY1)).toEqual({ ok: false, used: 3 });
  });

  it("refuses when either key is exhausted (new token, same IP)", async () => {
    const u = usage();
    for (let i = 0; i < 3; i++) await u.consume(["tok1", "ip"], 3, DAY1);
    expect((await u.consume(["tok2", "ip"], 3, DAY1)).ok).toBe(false);
    expect((await u.consume(["tok2", "other-ip"], 3, DAY1)).ok).toBe(true);
  });

  it("grants as many as are left, across every key", async () => {
    const u = usage();
    await u.consume(["tok", "ip"], 10, DAY1);
    await u.consume(["other", "ip"], 10, DAY1); // ip is at 2, tok at 1
    expect(await u.consumeUpTo(["tok", "ip"], 10, 5, DAY1)).toEqual({ granted: 5, used: 7 });
    expect(await u.consumeUpTo(["tok", "ip"], 10, 5, DAY1)).toEqual({ granted: 3, used: 10 });
    expect(await u.consumeUpTo(["tok", "ip"], 10, 5, DAY1)).toEqual({ granted: 0, used: 10 });
  });

  it("resets the next UTC day", async () => {
    const u = usage();
    for (let i = 0; i < 3; i++) await u.consume(["k"], 3, DAY1);
    expect((await u.consume(["k"], 3, DAY1 + 24 * 60 * MIN)).ok).toBe(true);
  });
});
