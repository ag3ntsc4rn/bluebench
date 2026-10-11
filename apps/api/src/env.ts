import type { ProviderQuota, UsageCounter } from "./quota.ts";

export interface Env {
  ASSETS: Fetcher;
  /** Cached per-source verdicts, keyed by a hash of the indicator. Never counters (1,000 writes/day). */
  VERDICTS: KVNamespace;
  /** One instance per upstream provider: per-minute rate and daily budget. */
  PROVIDER_QUOTA: DurableObjectNamespace<ProviderQuota>;
  /** Daily lookup caps per session and per IP. */
  USAGE: DurableObjectNamespace<UsageCounter>;
  TOKEN_LIMITER: RateLimit;
  IP_LIMITER: RateLimit;

  /** Public Turnstile site key (wrangler var). Empty until the owner creates the widget. */
  TURNSTILE_SITE_KEY: string;
  // Wrangler secrets. Missing ones switch the feature or source off, never crash.
  TURNSTILE_SECRET_KEY?: string;
  SESSION_SECRET?: string;
  ABUSECH_AUTH_KEY?: string;
  SAFE_BROWSING_API_KEY?: string;
}
