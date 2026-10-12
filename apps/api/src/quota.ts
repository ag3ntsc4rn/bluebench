import { DurableObject } from "cloudflare:workers";
import type { SourceId } from "@bluebench/shared";
import type { Env } from "./env.ts";

export type Tier = "anon" | "user";

export interface ProviderLimits {
  /** Steady per-minute rate (token bucket refill); also the burst size. */
  perMinute: number;
  /** Upstream calls per UTC day. */
  perDay: number;
}

/** Everything with a ProviderQuota instance: the lookup sources, plus the CT search services for domain reports. */
export type QuotaKey = SourceId | "crtsh" | "certspotter";

/**
 * Kept well inside each provider's terms: abuse.ch asks for modest volume; Safe Browsing's default
 * quota is 10k/day; crt.sh publishes no limit but asks for restraint (~5/min), and results are cached 24 h.
 * Cert Spotter (only when crt.sh fails) limits queries per hour; one permit covers a check's few pages.
 */
export const PROVIDER_LIMITS: Readonly<Record<QuotaKey, ProviderLimits>> = {
  urlhaus: { perMinute: 30, perDay: 3000 },
  threatfox: { perMinute: 30, perDay: 3000 },
  malwarebazaar: { perMinute: 30, perDay: 3000 },
  safebrowsing: { perMinute: 60, perDay: 8000 },
  crtsh: { perMinute: 5, perDay: 1000 },
  certspotter: { perMinute: 1, perDay: 500 },
};

/** Anonymous traffic may spend at most this share of a provider's daily budget. */
export const ANON_SHARE = 0.6;

/** Lookups per UTC day for an anonymous session or IP group. */
export const ANON_DAILY_LIMIT = 100;

/** Lookups per UTC day for a signed-in account. */
export const USER_DAILY_LIMIT = 300;

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

  acquire(source: QuotaKey, tier: Tier, now = Date.now()): { ok: true } | { ok: false; reason: QuotaDenial } {
    const limits = PROVIDER_LIMITS[source];
    const day = utcDay(now);
    const sql = this.ctx.storage.sql;
    const row = sql.exec<{ total: number; anon: number }>("SELECT total, anon FROM daily WHERE day = ?", day).toArray()[0];
    const total = row?.total ?? 0;
    const anon = row?.anon ?? 0;
    if (total >= limits.perDay) return { ok: false, reason: "daily" };
    if (tier === "anon" && anon >= Math.floor(limits.perDay * ANON_SHARE)) return { ok: false, reason: "daily" };

    const perMs = limits.perMinute / 60_000;
    this.tokens = Math.min(limits.perMinute, (this.tokens ?? limits.perMinute) + (now - this.refilledAt) * perMs);
    this.refilledAt = now;
    if (this.tokens < 1) return { ok: false, reason: "rate" };
    this.tokens -= 1;

    sql.exec(
      `INSERT INTO daily (day, total, anon) VALUES (?, 1, ?)
       ON CONFLICT(day) DO UPDATE SET total = total + 1, anon = anon + excluded.anon`,
      day,
      tier === "anon" ? 1 : 0,
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
