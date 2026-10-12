import { Hono } from "hono";
import { setCookie } from "hono/cookie";
import {
  ByoRequestSchema,
  canonicalDomain,
  orgDomain,
  canonicalIndicator,
  DomainRequestSchema,
  sha256Hex,
  LookupRequestSchema,
  SECURITY_HEADERS,
  SessionRequestSchema,
  type ByoResponse,
  type DomainReport,
  type HealthResponse,
  type LookupResponse,
} from "@bluebench/shared";
import { account } from "./account.ts";
import { relay } from "./byo.ts";
import type { Env } from "./env.ts";
import { domainReport, hasCachedReport } from "./domain/report.ts";
import { admit, challenge, chargeDaily, clientIp, fail, notConfigured, readJson } from "./http.ts";
import { lookup } from "./lookup.ts";
import { tick } from "./monitor/run.ts";
import { SESSION_COOKIE, SESSION_TTL_SECONDS, signSession, verifyTurnstile } from "./session.ts";

export { ProviderQuota, UsageCounter } from "./quota.ts";
export type { Env };
// Only handlers and Durable Object classes may be exported from the main module; workerd refuses anything else.

const app = new Hono<{ Bindings: Env }>().basePath("/api");

// Security headers on every API response, including 404s and errors.
app.use("*", async (c, next) => {
  await next();
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    c.res.headers.set(name, value);
  }
  c.res.headers.set("Cache-Control", "no-store");
});

/** Reject cross-site requests outright (the session cookies are also SameSite=Strict). */
app.use("*", async (c, next) => {
  const origin = c.req.header("origin");
  if (c.req.method !== "GET" && origin && origin !== new URL(c.req.url).origin) {
    return fail(c, 403, { error: "invalid", message: "Cross-site request refused." });
  }
  await next();
});

app.get("/health", (c) => c.json<HealthResponse>({ ok: true }));

/** Exchange a Turnstile token for a short-lived signed session cookie. */
app.post("/session", async (c) => {
  const { TURNSTILE_SITE_KEY, TURNSTILE_SECRET_KEY, SESSION_SECRET } = c.env;
  if (!TURNSTILE_SITE_KEY || !TURNSTILE_SECRET_KEY || !SESSION_SECRET) return notConfigured(c);

  if (!(await c.env.IP_LIMITER.limit({ key: `session:${clientIp(c)}` })).success) {
    return fail(c, 429, { error: "rate-limited", message: "Too many attempts. Wait a minute and try again.", retryAfter: 60 });
  }
  const body = await readJson(c);
  if (!body.ok) return body.res;
  const parsed = SessionRequestSchema.safeParse(body.data);
  if (!parsed.success) return fail(c, 400, { error: "invalid", message: "Missing bot check token." });
  if (!(await verifyTurnstile(TURNSTILE_SECRET_KEY, parsed.data.turnstileToken))) {
    return challenge(c, "The bot check didn't go through. Please try again.");
  }

  const { token } = await signSession(SESSION_SECRET);
  setCookie(c, SESSION_COOKIE, token, {
    prefix: "host",
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
  });
  return c.json({ ok: true });
});

app.post("/lookup", async (c) => {
  const a = await admit(c);
  if (!a.ok) return a.res;

  const body = await readJson(c);
  if (!body.ok) return body.res;
  const parsed = LookupRequestSchema.safeParse(body.data);
  const value = parsed.success ? canonicalIndicator(parsed.data) : null;
  if (!parsed.success || !value) {
    return fail(c, 400, { error: "invalid", message: "That isn't something we can look up. Public IPs, domains, URLs and file hashes only." });
  }

  const overDaily = await chargeDaily(c, a);
  if (overDaily) return overDaily;

  const result = await lookup(parsed.data.kind, value, {
    env: c.env,
    tier: a.tier,
    waitUntil: (p) => c.executionCtx.waitUntil(p),
  });
  return c.json<LookupResponse>(result);
});

/**
 * Bring-your-own-key relay for providers that don't allow cross-site calls (VirusTotal, AbuseIPDB,
 * GreyNoise). Needs a session and counts toward the per-minute limits, but not the daily cap: it
 * spends the user's quota, not ours. The keys and the indicator are passed on and never stored.
 */
app.post("/byo", async (c) => {
  const a = await admit(c);
  if (!a.ok) return a.res;

  const body = await readJson(c);
  if (!body.ok) return body.res;
  const parsed = ByoRequestSchema.safeParse(body.data);
  const value = parsed.success ? canonicalIndicator(parsed.data) : null;
  if (!parsed.success || !value) {
    return fail(c, 400, { error: "invalid", message: "That isn't something we can look up with your keys." });
  }
  return c.json<ByoResponse>({ ok: true, sources: await relay(parsed.data, value) });
});

/** Domain report card: DNS, email authentication, HTTPS, headers and certificate checks. */
app.post("/domain", async (c) => {
  const a = await admit(c);
  if (!a.ok) return a.res;

  const body = await readJson(c);
  if (!body.ok) return body.res;
  const parsed = DomainRequestSchema.safeParse(body.data);
  const domain = parsed.success ? canonicalDomain(parsed.data.domain) : null;
  if (!domain) return fail(c, 400, { error: "invalid", message: "Enter a domain name, like example.com." });

  // Cap fresh checks per target, so nobody can use Bluebench to hammer someone else's site.
  if (!(await hasCachedReport(c.env, domain))) {
    const byTarget = await c.env.TARGET_LIMITER.limit({ key: await sha256Hex(domain) });
    if (!byTarget.success) {
      return fail(c, 429, {
        error: "rate-limited",
        message: "This domain has been checked a lot in the last minute. Try again shortly.",
        retryAfter: 60,
      });
    }
  }

  const overDaily = await chargeDaily(c, a);
  if (overDaily) return overDaily;

  const report = await domainReport(domain, {
    env: c.env,
    tier: a.tier,
    waitUntil: (p) => c.executionCtx.waitUntil(p),
    selfZone: orgDomain(new URL(c.req.url).hostname),
  });
  return c.json<DomainReport>(report);
});

app.route("/", account);

app.notFound((c) => c.json({ ok: false, error: "Not found" }, 404));

// Never echo request details or stack traces; nothing pasted is logged.
app.onError((_err, c) => c.json({ ok: false, error: "Internal error" }, 500));

export default {
  fetch: app.fetch,
  /** Every minute: deliver pending alerts, or re-check the next due domain (see monitor/run.ts). */
  async scheduled(controller, env, ctx) {
    await tick(env, { now: controller.scheduledTime, waitUntil: (p) => ctx.waitUntil(p) });
  },
} satisfies ExportedHandler<Env>;
