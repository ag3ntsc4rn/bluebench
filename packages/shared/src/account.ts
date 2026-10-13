import { z } from "zod";
import type { Grade } from "./domain-report.ts";

/** Saved domains per account. Monitoring needs each one verified with a DNS TXT record. */
export const MAX_SAVED_DOMAINS = 5;
/** Push subscriptions (browsers/devices) per account. */
export const MAX_PUSH_SUBSCRIPTIONS = 5;
/** The TXT record value that proves control of a domain: `bluebench-verify=<token>`. */
export const VERIFY_PREFIX = "bluebench-verify=";

export const SignInRequestSchema = z.strictObject({
  email: z.email().max(254),
});

export const VerifySignInSchema = z.strictObject({
  token: z.string().min(16).max(128).regex(/^[A-Za-z0-9_-]+$/),
});

/** The 6-digit code from the sign-in email, for the installed app (iOS opens email links in Safari, not the app). */
export const SignInCodeSchema = z.strictObject({
  email: z.email().max(254),
  code: z.string().regex(/^\d{6}$/),
});

export const SaveDomainSchema = z.strictObject({
  domain: z.string().min(1).max(253),
});

export const AccountSettingsSchema = z.strictObject({
  emailAlerts: z.boolean(),
});

/**
 * Hosts of the browser push services we deliver to. A subscription endpoint is a URL our server
 * will POST to, so anything else is refused (otherwise it's an SSRF hole).
 */
const PUSH_HOSTS: readonly RegExp[] = [
  /^fcm\.googleapis\.com$/, // Chrome, Edge (Chromium), Android
  /^updates\.push\.services\.mozilla\.com$/, // Firefox
  /^web\.push\.apple\.com$/, // Safari, iOS home-screen apps
  /^[a-z0-9-]+\.notify\.windows\.com$/, // legacy Edge / Windows
];

export function isPushEndpoint(endpoint: string): boolean {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return false;
  }
  return url.protocol === "https:" && url.port === "" && !url.username && !url.password && PUSH_HOSTS.some((h) => h.test(url.hostname));
}

const b64url = (min: number, max: number) => z.string().min(min).max(max).regex(/^[A-Za-z0-9_-]+=*$/);

/** What `PushSubscription.toJSON()` gives us (expirationTime is ignored). */
export const PushSubscriptionSchema = z.object({
  endpoint: z.string().max(2048).refine(isPushEndpoint, "Unsupported push service"),
  keys: z.object({
    p256dh: b64url(80, 100), // 65-byte P-256 point
    auth: b64url(16, 32), // 16-byte secret
  }),
});
export type PushSubscriptionJson = z.infer<typeof PushSubscriptionSchema>;

export const PushUnsubscribeSchema = z.strictObject({
  endpoint: z.string().max(2048),
});

export type Me =
  | { ok: true; signedIn: false; accountsEnabled: boolean }
  | {
      ok: true;
      signedIn: true;
      accountsEnabled: true;
      email: string;
      emailAlerts: boolean;
      /** VAPID public key (base64url), or null when push isn't configured. */
      pushKey: string | null;
    };

export interface SavedDomain {
  id: string;
  domain: string;
  /** The full TXT record value to publish at the domain. */
  verifyRecord: string;
  verified: boolean;
  /** From the last daily check; null until the first one. */
  grade: Grade | null;
  score: number | null;
  lastCheckedAt: string | null;
  certExpiresAt: string | null;
  /** Lookalike domains with a website or mail, from the daily watcher. */
  lookalikes: LookalikeHit[];
  /** When the last full lookalike scan finished; null until the first one. */
  lookalikesScannedAt: string | null;
  createdAt: string;
}

export interface LookalikeHit {
  domain: string;
  /** Has an A record. */
  web: boolean;
  /** Has an MX record (can send or receive mail as that name). */
  mail: boolean;
  firstSeenAt: string;
}

export type AlertKind = "grade-drop" | "cert-expiry" | "verification-lost" | "lookalike" | "kev" | "test";

export interface AlertItem {
  id: string;
  domain: string | null;
  kind: AlertKind;
  title: string;
  body: string;
  createdAt: string;
  /** How it reached the user: null while still pending. */
  channel: "push" | "email" | "none" | null;
}

export interface DomainsResponse {
  ok: true;
  domains: SavedDomain[];
}

export interface AlertsResponse {
  ok: true;
  alerts: AlertItem[];
}
