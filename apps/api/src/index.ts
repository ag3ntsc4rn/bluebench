import { Hono, type Context } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import {
  canonicalDomain,
  canonicalIndicator,
  DomainRequestSchema,
  sha256Hex,
  ipRateKey,
  LookupRequestSchema,
  MAX_PASTE_LENGTH,
  SECURITY_HEADERS,
  SessionRequestSchema,
  type ApiError,
  type DomainReport,
  type HealthResponse,
  type LookupResponse,
} from "@bluebench/shared";
import type { Env } from "./env.ts";
import { domainReport, hasCachedReport } from "./domain/report.ts";
import { lookup } from "./lookup.ts";
import { ANON_DAILY_LIMIT } from "./quota.ts";
import { hmac, SESSION_COOKIE, SESSION_TTL_SECONDS, signSession, verifySession, verifyTurnstile } from "./session.ts";

export { ProviderQuota, UsageCounter } from "./quota.ts";
export type { Env };
// Only handlers and Durable Object classes may be exported from the main module; workerd refuses anything else.

type Ctx = Context<{ Bindings: Env }>;

const app = new Hono<{ Bindings: Env }>().basePath("/api");

// Security headers on every API response, including 404s and errors.
app.use("*", async (c, next) => {
  await next();
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    c.res.headers.set(name, value);
  }
  c.res.headers.set("Cache-Control", "no-store");
});

function fail(c: Ctx, status: 400 | 401 | 403 | 413 | 415 | 429 | 503, body: Omit<ApiError, "ok">) {
  if (body.retryAfter) c.header("Retry-After", String(body.retryAfter));
  return c.json<ApiError>({ ok: false, ...body }, status);
}

const challenge = (c: Ctx, message = "Please complete a quick bot check.") =>
  fail(c, 401, { error: "challenge", message, siteKey: c.env.TURNSTILE_SITE_KEY });

const notConfigured = (c: Ctx) =>
  fail(c, 503, { error: "unavailable", message: "Reputation lookups aren't switched on yet. The browser tools still work." });

/** Read a small JSON body: must be declared JSON (forces a CORS preflight cross-site) and under the paste cap. */
async function readJson(c: Ctx): Promise<{ ok: true; data: unknown } | { ok: false; res: Response }> {
  if (!c.req.header("content-type")?.toLowerCase().startsWith("application/json")) {
    return { ok: false, res: fail(c, 415, { error: "invalid", message: "Expected JSON." }) };
  }
  const text = await c.req.text();
  if (text.length > MAX_PASTE_LENGTH) return { ok: false, res: fail(c, 413, { error: "invalid", message: "Request too large." }) };
  try {
    return { ok: true, data: JSON.parse(text) };
  } catch {
    return { ok: false, res: fail(c, 400, { error: "invalid", message: "Expected JSON." }) };
  }
}

/** Reject cross-site requests outright (the session cookie is also SameSite=Strict). */
app.use("*", async (c, next) => {
  const origin = c.req.header("origin");
  if (c.req.method !== "GET" && origin && origin !== new URL(c.req.url).origin) {
    return fail(c, 403, { error: "invalid", message: "Cross-site request refused." });
  }
  await next();
});

const clientIp = (c: Ctx) => ipRateKey(c.req.header("cf-connecting-ip") ?? "");

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

type Admitted = { ok: true; sessionId: string; ipKey: string; secret: string } | { ok: false; res: Response };

/** Gate for anything that costs upstream calls: configured, a valid session, and within per-minute limits. */
async function admit(c: Ctx): Promise<Admitted> {
  const { TURNSTILE_SITE_KEY, SESSION_SECRET } = c.env;
  if (!TURNSTILE_SITE_KEY || !SESSION_SECRET) return { ok: false, res: notConfigured(c) };

  // No token, no lookups.
  const session = await verifySession(SESSION_SECRET, getCookie(c, SESSION_COOKIE, "host"));
  if (!session) return { ok: false, res: challenge(c) };

  const ipKey = clientIp(c);
  const [byToken, byIp] = await Promise.all([
    c.env.TOKEN_LIMITER.limit({ key: session.id }),
    c.env.IP_LIMITER.limit({ key: `lookup:${ipKey}` }),
  ]);
  if (!byToken.success || !byIp.success) {
    return {
      ok: false,
      res: fail(c, 429, { error: "rate-limited", message: "That's a lot of checks in a minute. Wait a moment and try again.", retryAfter: 60 }),
    };
  }
  return { ok: true, sessionId: session.id, ipKey, secret: SESSION_SECRET };
}

/** Count one lookup or domain check against today's caps. Counters are keyed by HMACs, so no session ids or IPs are stored. */
async function chargeDaily(c: Ctx, a: Extract<Admitted, { ok: true }>): Promise<Response | null> {
  const keys = await Promise.all([hmac(a.secret, `s:${a.sessionId}`), hmac(a.secret, `ip:${a.ipKey}`)]);
  const usage = c.env.USAGE.get(c.env.USAGE.idFromName("daily"));
  const quota = await usage.consume(keys, ANON_DAILY_LIMIT);
  if (quota.ok) return null;
  return fail(c, 429, {
    error: "daily-limit",
    message: `You've used today's ${ANON_DAILY_LIMIT} free lookups and checks. They reset at midnight UTC. Signing in and your own API keys are coming soon.`,
  });
}

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
    tier: "anon",
    waitUntil: (p) => c.executionCtx.waitUntil(p),
  });
  return c.json<LookupResponse>(result);
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

  const report = await domainReport(domain, { env: c.env, tier: "anon", waitUntil: (p) => c.executionCtx.waitUntil(p) });
  return c.json<DomainReport>(report);
});

app.notFound((c) => c.json({ ok: false, error: "Not found" }, 404));

// Never echo request details or stack traces; nothing pasted is logged.
app.onError((_err, c) => c.json({ ok: false, error: "Internal error" }, 500));

/** Apply our security headers to a response from another layer (e.g. static assets). */
function withSecurityHeaders(res: Response): Response {
  const out = new Response(res.body, res);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) out.headers.set(name, value);
  return out;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/api" || url.pathname.startsWith("/api/")) return app.fetch(request, env, ctx);

    // Visitors' page requests never get here: run_worker_first covers /api/* only, and Cloudflare's edge
    // redirects http to https and serves the static files. But when this Worker fetches its own domain
    // (a domain report on bluebench.dev), the request comes straight back here. Behave like the edge so
    // the report sees the real site.
    if (url.protocol === "http:") {
      url.protocol = "https:";
      return Response.redirect(url.href, 301);
    }
    return withSecurityHeaders(await env.ASSETS.fetch(request));
  },
} satisfies ExportedHandler<Env>;
