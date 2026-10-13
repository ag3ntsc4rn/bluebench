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
  /** Fresh domain reports per target domain (keyed by its hash), so we can't be used to hammer a site. */
  TARGET_LIMITER: RateLimit;
  /** Accounts, saved domains, alerts and push subscriptions. */
  DB: D1Database;

  /** Public Turnstile site key (wrangler var). Empty until the owner creates the widget. */
  TURNSTILE_SITE_KEY: string;
  /** e.g. https://bluebench.dev: magic links point here, and it's the zone we can't grade from inside. */
  SITE_ORIGIN: string;
  /** "Name <address>" for magic links and alert emails. */
  EMAIL_FROM: string;
  /** Web Push VAPID public key (base64url). Empty = push off; alerts fall back to email. */
  VAPID_PUBLIC_KEY: string;
  // Wrangler secrets. Missing ones switch the feature or source off, never crash.
  TURNSTILE_SECRET_KEY?: string;
  SESSION_SECRET?: string;
  ABUSECH_AUTH_KEY?: string;
  SAFE_BROWSING_API_KEY?: string;
  /** Signs account session cookies. Missing = accounts switched off. */
  BETTER_AUTH_SECRET?: string;
  /** Resend API key for magic links and alert emails. Missing = accounts switched off (no way to sign in). */
  RESEND_API_KEY?: string;
  /** SSLMate Cert Spotter API key: the certificate check's fallback when crt.sh fails. Missing = crt.sh only. */
  CERTSPOTTER_API_KEY?: string;
  /** Web Push VAPID private key (base64url, 32 bytes). */
  VAPID_PRIVATE_KEY?: string;
}
