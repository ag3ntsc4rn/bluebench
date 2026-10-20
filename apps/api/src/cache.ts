import type { Env } from "./env.ts";
import type { Tier } from "./quota.ts";

/**
 * Write a cache entry to KV in the background, if today's write budget allows. KV gives the free plan
 * 1,000 writes a day, shared with the Intel workflow; past that every write fails until midnight UTC,
 * including the KEV update. So each cache write first takes a permit from the `kv-writes` quota object
 * (900 a day), and without one the entry just isn't cached. A failed write only means a cache miss later.
 */
export function cachePut(
  deps: { env: Env; tier: Tier; waitUntil(p: Promise<unknown>): void },
  key: string,
  value: string,
  ttlSeconds: number,
): void {
  const { env } = deps;
  deps.waitUntil(
    (async () => {
      const permit = await env.PROVIDER_QUOTA.get(env.PROVIDER_QUOTA.idFromName("kv-writes")).acquire("kv-writes", deps.tier);
      if (permit.ok) await env.VERDICTS.put(key, value, { expirationTtl: ttlSeconds });
    })().catch(() => {}),
  );
}
