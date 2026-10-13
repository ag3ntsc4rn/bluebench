import { DurableObject } from "cloudflare:workers";
import type { SourceId } from "@bluebench/shared";
import type { Env } from "./env.ts";

export type Tier = "anon" | "user";

export interface ProviderLimits {
  /** Steady per-minute rate (token bucket refill). */
  perMinute: number;
  /** Bucket size: the most calls in a burst. Defaults to perMinute. */
  burst?: number;
  /** Upstream calls per UTC day. */
  perDay: number;
}

/** Everything with a ProviderQuota instance: the lookup sources, plus the CT search services for domain reports. */
export type QuotaKey = SourceId | "crtsh" | "certspotter";

/**
 * Kept well inside each provider's terms: abuse.ch asks for modest volume; Safe Browsing's default
 * quota is 10k/day; crt.sh publishes no limit but asks for restraint (~5/min), and results are cached 24 h.
 * Cert Spotter (only when crt.sh fails): its free plan allows 100 single-hostname queries an hour; we use
 * at most 90, counting each page of a check.
 */
export const PROVIDER_LIMITS: Readonly<Record<QuotaKey, ProviderLimits>> = {
  urlhaus: { perMinute: 30, perDay: 3000 },
  threatfox: { perMinute: 30, perDay: 3000 },
  malwarebazaar: { perMinute: 30, perDay: 3000 },
  safebrowsing: { perMinute: 60, perDay: 8000 },
  crtsh: { perMinute: 5, perDay: 1000 },
  certspotter: { perMinute: 1.5, burst: 4, perDay: 2000 },
};

/** Anonymous traffic may spend at most this share of a provider's daily budget. */
export const ANON_SHARE = 0.6;

// Daily lookup caps live in shared so the web app can state them.
export { ANON_DAILY_LIMIT, USER_DAILY_LIMIT } from "@bluebench/shared";

export type QuotaDenial = "rate" | "daily";

export const utcDay = (now = Date.now()) => new Date(now).toISOString().slice(0, 10);

/**
 * One instance per upstream provider (idFromName(source)). Grants permission for a single
 * upstream call; the Worker makes the call. The bucket lives in memory (a reset after eviction
 * is harmless); daily totals are persisted so the budget survives restarts.
 */
export class ProviderQuota extends DurableObject<Env> {
  private tokens: number | null = null;
  private refilledAt = 0;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS daily (day TEXT PRIMARY KEY, total INTEGER NOT NULL, anon INTEGER NOT NULL)",
    );
  }

  /** Permission for `cost` upstream calls at once (all or nothing). */
  acquire(source: QuotaKey, tier: Tier, now = Date.now(), cost = 1): { ok: true } | { ok: false; reason: QuotaDenial } {
    const limits = PROVIDER_LIMITS[source];
    const day = utcDay(now);
    const sql = this.ctx.storage.sql;
    const row = sql.exec<{ total: number; anon: number }>("SELECT total, anon FROM daily WHERE day = ?", day).toArray()[0];
    const total = row?.total ?? 0;
    const anon = row?.anon ?? 0;
    if (total + cost > limits.perDay) return { ok: false, reason: "daily" };
    if (tier === "anon" && anon + cost > Math.floor(limits.perDay * ANON_SHARE)) return { ok: false, reason: "daily" };

    const burst = limits.burst ?? limits.perMinute;
    const perMs = limits.perMinute / 60_000;
    this.tokens = Math.min(burst, (this.tokens ?? burst) + (now - this.refilledAt) * perMs);
    this.refilledAt = now;
    if (this.tokens < cost) return { ok: false, reason: "rate" };
    this.tokens -= cost;

    sql.exec(
      `INSERT INTO daily (day, total, anon) VALUES (?, ?, ?)
       ON CONFLICT(day) DO UPDATE SET total = total + excluded.total, anon = anon + excluded.anon`,
      day,
      cost,
      tier === "anon" ? cost : 0,
    );
    if (!row) sql.exec("DELETE FROM daily WHERE day < ?", day); // first call of a new day: drop old rows
    return { ok: true };
  }
}

/**
 * Daily lookup caps. Keys are HMACs of the session id and the IP group, so no raw IPs are stored.
 * A single instance is plenty at free-tier volumes (Workers caps us at 100k requests/day anyway).
 */
export class UsageCounter extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS usage (day TEXT NOT NULL, key TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (day, key))",
    );
  }

  /** Count one lookup against every key, unless any key is already at `limit`. */
  consume(keys: string[], limit: number, now = Date.now()): { ok: boolean; used: number } {
    return this.consumeLimits(
      keys.map((k) => [k, limit]),
      now,
    );
  }

  /**
   * Grant up to `wanted` units against every key (bulk lookups): as many as the fullest key has left.
   * Returns how many were granted (0 at the limit) and the highest count afterwards.
   */
  consumeUpTo(keys: string[], limit: number, wanted: number, now = Date.now()): { granted: number; used: number } {
    const day = utcDay(now);
    const sql = this.ctx.storage.sql;
    let used = 0;
    for (const key of keys) {
      used = Math.max(used, sql.exec<{ n: number }>("SELECT n FROM usage WHERE day = ? AND key = ?", day, key).toArray()[0]?.n ?? 0);
    }
    const granted = Math.max(0, Math.min(wanted, limit - used));
    if (granted === 0) return { granted, used };
    for (const key of keys) {
      sql.exec("INSERT INTO usage (day, key, n) VALUES (?, ?, ?) ON CONFLICT(day, key) DO UPDATE SET n = n + excluded.n", day, key, granted);
    }
    if (used === 0) sql.exec("DELETE FROM usage WHERE day < ?", day);
    return { granted, used: used + granted };
  }

  /** Count one against every key, unless any key is already at its own limit. `used` is the highest count. */
  consumeLimits(limits: [key: string, limit: number][], now = Date.now()): { ok: boolean; used: number } {
    const day = utcDay(now);
    const sql = this.ctx.storage.sql;
    let used = 0;
    let over = false;
    for (const [key, limit] of limits) {
      const n = sql.exec<{ n: number }>("SELECT n FROM usage WHERE day = ? AND key = ?", day, key).toArray()[0]?.n ?? 0;
      used = Math.max(used, n);
      if (n >= limit) over = true;
    }
    if (over) return { ok: false, used };
    for (const [key] of limits) {
      sql.exec(
        "INSERT INTO usage (day, key, n) VALUES (?, ?, 1) ON CONFLICT(day, key) DO UPDATE SET n = n + 1",
        day,
        key,
      );
    }
    if (used === 0) sql.exec("DELETE FROM usage WHERE day < ?", day);
    return { ok: true, used: used + 1 };
  }
}
