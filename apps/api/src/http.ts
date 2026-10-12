import type { Context } from "hono";
import { getCookie } from "hono/cookie";
import { ipRateKey, MAX_PASTE_LENGTH, type ApiError } from "@bluebench/shared";
import { currentUser, type AccountUser } from "./auth.ts";
import type { Env } from "./env.ts";
import { ANON_DAILY_LIMIT, USER_DAILY_LIMIT, type Tier } from "./quota.ts";
import { hmac, SESSION_COOKIE, verifySession } from "./session.ts";

export type Ctx = Context<{ Bindings: Env }>;

export function fail(c: Ctx, status: 400 | 401 | 403 | 404 | 409 | 413 | 415 | 429 | 503, body: Omit<ApiError, "ok">) {
  if (body.retryAfter) c.header("Retry-After", String(body.retryAfter));
  return c.json<ApiError>({ ok: false, ...body }, status);
}

export const challenge = (c: Ctx, message = "Please complete a quick bot check.") =>
  fail(c, 401, { error: "challenge", message, siteKey: c.env.TURNSTILE_SITE_KEY });

export const notConfigured = (c: Ctx) =>
  fail(c, 503, { error: "unavailable", message: "Reputation lookups aren't switched on yet. The browser tools still work." });

export const tooFast = (c: Ctx, message = "That's a lot of checks in a minute. Wait a moment and try again.") =>
  fail(c, 429, { error: "rate-limited", message, retryAfter: 60 });

/** Read a small JSON body: must be declared JSON (forces a CORS preflight cross-site) and under the paste cap. */
export async function readJson(c: Ctx): Promise<{ ok: true; data: unknown } | { ok: false; res: Response }> {
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

export const clientIp = (c: Ctx) => ipRateKey(c.req.header("cf-connecting-ip") ?? "");

export type Admitted =
  | { ok: true; tier: Tier; user: AccountUser | null; sessionId: string; ipKey: string; secret: string }
  | { ok: false; res: Response };

/**
 * Gate for anything that costs upstream calls: configured, a valid session, and within per-minute limits.
 * A signed-in account counts as a session (it passed the bot check to sign in); otherwise the
 * anonymous Turnstile session cookie is required.
 */
export async function admit(c: Ctx, opts: { anonOnly?: boolean } = {}): Promise<Admitted> {
  const { TURNSTILE_SITE_KEY, SESSION_SECRET } = c.env;
  if (!TURNSTILE_SITE_KEY || !SESSION_SECRET) return { ok: false, res: notConfigured(c) };

  const ipKey = clientIp(c);
  const user = opts.anonOnly ? null : await currentUser(c.env, c.req.raw.headers);
  let sessionId: string;
  if (user) {
    sessionId = `u:${user.id}`;
  } else {
    // No token, no lookups.
    const session = await verifySession(SESSION_SECRET, getCookie(c, SESSION_COOKIE, "host"));
    if (!session) return { ok: false, res: challenge(c) };
    sessionId = session.id;
  }

  const [byToken, byIp] = await Promise.all([
    c.env.TOKEN_LIMITER.limit({ key: sessionId }),
    c.env.IP_LIMITER.limit({ key: `lookup:${ipKey}` }),
  ]);
  if (!byToken.success || !byIp.success) return { ok: false, res: tooFast(c) };
  return { ok: true, tier: user ? "user" : "anon", user, sessionId, ipKey, secret: SESSION_SECRET };
}

/**
 * Count one lookup or domain check against today's caps. Counters are keyed by HMACs, so no session
 * ids, account ids or IPs are stored. Accounts are capped per account only, so a shared office IP
 * doesn't hold them to the anonymous limit.
 */
export async function chargeDaily(c: Ctx, a: Extract<Admitted, { ok: true }>): Promise<Response | null> {
  const usage = c.env.USAGE.get(c.env.USAGE.idFromName("daily"));
  if (a.user) {
    const quota = await usage.consume([await hmac(a.secret, `u:${a.user.id}`)], USER_DAILY_LIMIT);
    if (quota.ok) return null;
    return fail(c, 429, {
      error: "daily-limit",
      message: `You've used today's ${USER_DAILY_LIMIT} lookups and checks. They reset at midnight UTC.`,
    });
  }
  const keys = await Promise.all([hmac(a.secret, `s:${a.sessionId}`), hmac(a.secret, `ip:${a.ipKey}`)]);
  const quota = await usage.consume(keys, ANON_DAILY_LIMIT);
  if (quota.ok) return null;
  return fail(c, 429, {
    error: "daily-limit",
    message: `You've used today's ${ANON_DAILY_LIMIT} free lookups and checks. They reset at midnight UTC. Sign in (free) for ${USER_DAILY_LIMIT} a day.`,
  });
}
