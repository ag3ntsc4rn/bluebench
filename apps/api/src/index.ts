import { Hono } from "hono";
import { setCookie } from "hono/cookie";
import {
  ByoRequestSchema,
  canonicalDomain,
  orgDomain,
  canonicalIndicator,
  DomainRequestSchema,
  KEV_KV_KEYS,
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
import { admit, challenge, chargeDaily, clientIp, fail, notConfigured, readJson, tooFast } from "./http.ts";
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
  // Nothing personal is cacheable; the few public routes set their own Cache-Control.
  if (!c.res.headers.has("Cache-Control")) c.res.headers.set("Cache-Control", "no-store");
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

/**
 * Known exploited vulnerabilities for the Intel tab: the last 90 days by default, the whole catalogue
 * with ?scope=all, or just the vendor/product names (watchlist picker) with ?scope=vendors. Built twice a day by .github/workflows/intel.yml and served from KV byte-for-byte (no
 * parsing). Public data, so no session; a per-IP limit stops it being used as a free mirror.
 */
app.get("/intel/kev", async (c) => {
  if (!(await c.env.IP_LIMITER.limit({ key: `intel:${clientIp(c)}` })).success) return tooFast(c);
  const q = c.req.query("scope");
  const scope = q === "all" || q === "vendors" ? q : "recent";
  // cacheTtl keeps a copy at the edge: an uncached read of the 1.1 MB catalogue takes seconds.
  const body = await c.env.VERDICTS.get(KEV_KV_KEYS[scope], { type: "stream", cacheTtl: 300 }).catch(() => null);
  if (!body) return fail(c, 503, { error: "unavailable", message: "The vulnerability list isn't loaded yet. Check back shortly." });
  return new Response(body, { headers: { "content-type": "application/json; charset=utf-8", "cache-control": "public, max-age=900" } });
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
