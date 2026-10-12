import {
  cacheKey,
  mergeVerdict,
  SOURCE_LABELS,
  SOURCES_FOR_KIND,
  type LookupKind,
  type LookupResponse,
  type SourceId,
  type SourceResult,
} from "@bluebench/shared";
import type { Env } from "./env.ts";
import { PROVIDERS, type ProviderAnswer } from "./providers.ts";
import type { QuotaDenial, Tier } from "./quota.ts";
import { redact, restore } from "./redact.ts";

const HOUR = 3600_000;
/** abuse.ch answers are fresh for 6 h, and may be served stale for up to 24 h when the live budget is spent. */
const ABUSECH_FRESH_MS = 6 * HOUR;
const ABUSECH_STALE_MS = 24 * HOUR;
/** KV's minimum TTL. Safe Browsing answers shorter than this aren't cached at all. */
const KV_MIN_TTL_S = 60;

interface CachedSource {
  result: SourceResult;
  /** Epoch ms. Served as-is until then. */
  freshUntil: number;
  /** Epoch ms. Served marked stale until then, only if the live call can't be made. Safe Browsing: same as freshUntil. */
  staleUntil: number;
}
type CacheEntry = Partial<Record<SourceId, CachedSource>>;

const SKIP_REASONS: Record<QuotaDenial | "unconfigured", string> = {
  unconfigured: "Not switched on for this server yet.",
  rate: "Busy right now. Try again in a minute.",
  daily: "Today's shared budget for this source is used up. It resets at midnight UTC. Signed-in accounts get a bigger share, and your own API keys (Settings) work any time.",
};

function cachePolicy(source: SourceId, answer: ProviderAnswer, now: number): { freshUntil: number; staleUntil: number } | null {
  if (source === "safebrowsing") {
    const s = answer.maxAgeSeconds ?? 0;
    return s >= KV_MIN_TTL_S ? { freshUntil: now + s * 1000, staleUntil: now + s * 1000 } : null;
  }
  return { freshUntil: now + ABUSECH_FRESH_MS, staleUntil: now + ABUSECH_STALE_MS };
}

export interface LookupDeps {
  env: Env;
  tier: Tier;
  waitUntil(p: Promise<unknown>): void;
  now?: () => number;
}

async function acquire(env: Env, source: SourceId, tier: Tier): Promise<QuotaDenial | null> {
  const stub = env.PROVIDER_QUOTA.get(env.PROVIDER_QUOTA.idFromName(source));
  const res = await stub.acquire(source, tier);
  return res.ok ? null : res.reason;
}

async function lookupUncoalesced(kind: LookupKind, value: string, deps: LookupDeps): Promise<LookupResponse> {
  const { env } = deps;
  const now = deps.now?.() ?? Date.now();
  const key = await cacheKey(kind, value);
  const cached: CacheEntry = (await env.VERDICTS.get<CacheEntry>(key, "json").catch(() => null)) ?? {};
  const fresh: CacheEntry = {};

  const fromCache = (c: CachedSource, stale: boolean): SourceResult => ({
    ...restore(c.result, value),
    cached: true,
    ...(stale ? { stale: true } : {}),
  });

  const sources = await Promise.all(
    SOURCES_FOR_KIND[kind].map(async (source): Promise<SourceResult> => {
      const label = SOURCE_LABELS[source];
      const provider = PROVIDERS[source];
      if (!provider.configured(env)) return { source, status: "skipped", summary: SKIP_REASONS.unconfigured, facts: [] };

      const hit = cached[source];
      if (hit && now < hit.freshUntil) return fromCache(hit, false);
      const staleOk = hit && now < hit.staleUntil ? hit : undefined;

      const denied = await acquire(env, source, deps.tier).catch((): QuotaDenial => "rate");
      if (denied) return staleOk ? fromCache(staleOk, true) : { source, status: "skipped", summary: SKIP_REASONS[denied], facts: [] };

      try {
        const answer = await provider.query(env, kind, value);
        const { maxAgeSeconds: _, ...shown } = answer;
        const result: SourceResult = { source, ...shown, checkedAt: new Date(now).toISOString() };
        const policy = cachePolicy(source, answer, now);
        if (policy) fresh[source] = { result: redact(result, value), ...policy };
        return result;
      } catch {
        if (staleOk) return fromCache(staleOk, true);
        return { source, status: "error", summary: `Couldn't reach ${label}. Try again shortly.`, facts: [] };
      }
    }),
  );

  if (Object.keys(fresh).length > 0) {
    // Merge with still-valid entries; KV keeps the whole entry until the longest of them expires.
    const merged: CacheEntry = { ...cached, ...fresh };
    for (const [s, c] of Object.entries(merged) as [SourceId, CachedSource][]) if (c.staleUntil <= now) delete merged[s];
    const ttl = Math.ceil((Math.max(...Object.values(merged).map((c) => c!.staleUntil)) - now) / 1000);
    // KV allows 1,000 writes/day on the free tier; a failed write just means a cache miss later.
    deps.waitUntil(env.VERDICTS.put(key, JSON.stringify(merged), { expirationTtl: Math.max(KV_MIN_TTL_S, ttl) }).catch(() => {}));
  }

  return { ok: true, kind, value, verdict: mergeVerdict(sources), sources };
}

/** Concurrent lookups of the same indicator in this isolate share one set of upstream calls. */
const inflight = new Map<string, Promise<LookupResponse>>();

export function lookup(kind: LookupKind, value: string, deps: LookupDeps): Promise<LookupResponse> {
  const k = `${deps.tier}:${kind}:${value}`;
  const existing = inflight.get(k);
  if (existing) return existing;
  const p = lookupUncoalesced(kind, value, deps).finally(() => inflight.delete(k));
  inflight.set(k, p);
  return p;
}
