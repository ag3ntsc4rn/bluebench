import { Hono } from "hono";
import {
  AccountSettingsSchema,
  canonicalDomain,
  MAX_PUSH_SUBSCRIPTIONS,
  MAX_SAVED_DOMAINS,
  PushSubscriptionSchema,
  PushUnsubscribeSchema,
  SaveDomainSchema,
  SignInRequestSchema,
  VerifySignInSchema,
  type AlertItem,
  type AlertsResponse,
  type DomainsResponse,
  type Me,
  type SavedDomain,
} from "@bluebench/shared";
import { and, asc, count, desc, eq, inArray } from "drizzle-orm";
import { accountsEnabled, currentUser, db, getAuth, MailFailed, type AccountUser } from "./auth.ts";
import { alert, domain, pushSubscription, user } from "./db/schema.ts";
import { Budget, Resolver } from "./dns.ts";
import type { Env } from "./env.ts";
import { admit, clientIp, fail, readJson, tooFast, type Ctx } from "./http.ts";
import { takeEmailQuota } from "./mail.ts";
import { pushToUser, vapidKeys } from "./monitor/run.ts";
import { hasVerifyRecord, newVerifyToken, verifyRecord } from "./monitor/verify.ts";
import { hmac } from "./session.ts";

/**
 * Accounts, saved domains, alerts and push subscriptions. Better Auth does the magic-link and session
 * work, but its HTTP handler is never mounted: these routes call it, so nothing else is exposed.
 */
export const account = new Hono<{ Bindings: Env }>();

/** Magic links per address, and per browser session, per UTC day. */
const SIGNIN_PER_EMAIL_DAILY = 5;
const SIGNIN_PER_SESSION_DAILY = 10;
/** Account changes (saving domains, push subscriptions, settings) per account per UTC day: D1 allows 100k row writes a day. */
const WRITES_PER_ACCOUNT_DAILY = 200;
const HISTORY_LIMIT = 50;

const accountsOff = (c: Ctx) =>
  fail(c, 503, { error: "unavailable", message: "Accounts aren't switched on yet. Everything else works without one." });

const signedOut = (c: Ctx) => fail(c, 401, { error: "signed-out", message: "You're signed out. Sign in again to continue." });

type UserGate = { ok: true; user: AccountUser } | { ok: false; res: Response };

async function requireUser(c: Ctx): Promise<UserGate> {
  if (!accountsEnabled(c.env)) return { ok: false, res: accountsOff(c) };
  const u = await currentUser(c.env, c.req.raw.headers);
  return u ? { ok: true, user: u } : { ok: false, res: signedOut(c) };
}

/** A signed-in user who may still make changes: 30 a minute and WRITES_PER_ACCOUNT_DAILY a day. */
async function requireWriter(c: Ctx): Promise<UserGate> {
  const g = await requireUser(c);
  if (!g.ok) return g;
  if (!(await c.env.IP_LIMITER.limit({ key: `write:${g.user.id}` })).success) {
    return { ok: false, res: tooFast(c, "That's a lot of changes in a minute. Wait a moment and try again.") };
  }
  const usage = c.env.USAGE.get(c.env.USAGE.idFromName("daily"));
  const key = await hmac(c.env.BETTER_AUTH_SECRET!, `writes:${g.user.id}`);
  if (!(await usage.consume([key], WRITES_PER_ACCOUNT_DAILY)).ok) {
    return { ok: false, res: fail(c, 429, { error: "daily-limit", message: "That's a lot of changes for one day. Try again tomorrow." }) };
  }
  return g;
}

function me(env: Env, u: AccountUser | null): Me {
  if (!u) return { ok: true, signedIn: false, accountsEnabled: accountsEnabled(env) };
  return { ok: true, signedIn: true, accountsEnabled: true, email: u.email, emailAlerts: u.emailAlerts, pushKey: vapidKeys(env)?.publicKey ?? null };
}

/** Copy Better Auth's Set-Cookie headers onto our response. */
function forwardCookies(c: Ctx, res: Response) {
  for (const value of res.headers.getSetCookie()) c.header("set-cookie", value, { append: true });
}

const iso = (d: Date | null) => (d ? d.toISOString() : null);

function toSavedDomain(row: typeof domain.$inferSelect): SavedDomain {
  return {
    id: row.id,
    domain: row.name,
    verifyRecord: verifyRecord(row.verifyToken),
    verified: row.verifiedAt !== null,
    grade: row.grade,
    score: row.score,
    lastCheckedAt: iso(row.lastCheckedAt),
    certExpiresAt: iso(row.certExpiresAt),
    createdAt: row.createdAt.toISOString(),
  };
}

account.get("/me", async (c) => c.json<Me>(me(c.env, await currentUser(c.env, c.req.raw.headers))));

/** Email a magic link. Needs the anonymous bot-check session, and is capped per address, per session and per day. */
account.post("/signin", async (c) => {
  if (!accountsEnabled(c.env)) return accountsOff(c);
  const a = await admit(c, { anonOnly: true });
  if (!a.ok) return a.res;

  const body = await readJson(c);
  if (!body.ok) return body.res;
  const parsed = SignInRequestSchema.safeParse(body.data);
  if (!parsed.success) return fail(c, 400, { error: "invalid", message: "Enter a valid email address." });
  const email = parsed.data.email.trim().toLowerCase();

  const usage = c.env.USAGE.get(c.env.USAGE.idFromName("daily"));
  const capped = await usage.consumeLimits([
    [await hmac(a.secret, `signin-email:${email}`), SIGNIN_PER_EMAIL_DAILY],
    [await hmac(a.secret, `signin-session:${a.sessionId}`), SIGNIN_PER_SESSION_DAILY],
  ]);
  if (!capped.ok) {
    return fail(c, 429, { error: "daily-limit", message: "That's a lot of sign-in links today. Use the newest one in your inbox, or try again tomorrow." });
  }
  if (!(await takeEmailQuota(c.env, "signin"))) {
    return fail(c, 429, { error: "daily-limit", message: "Bluebench has sent all the sign-in emails it can today. Please try again tomorrow." });
  }

  try {
    await getAuth(c.env).api.signInMagicLink({ body: { email }, headers: c.req.raw.headers });
  } catch (e) {
    const message = e instanceof MailFailed ? "We couldn't send the email just now. Try again in a few minutes." : "Something went wrong on our side. Try again shortly.";
    return fail(c, 503, { error: "unavailable", message });
  }
  return c.json({ ok: true });
});

/** Exchange a magic-link token (from the /signin page) for an account session cookie. */
account.post("/signin/verify", async (c) => {
  if (!accountsEnabled(c.env)) return accountsOff(c);
  if (!(await c.env.IP_LIMITER.limit({ key: `verify:${clientIp(c)}` })).success) return tooFast(c, "Too many attempts. Wait a minute and try again.");
  const body = await readJson(c);
  if (!body.ok) return body.res;
  const parsed = VerifySignInSchema.safeParse(body.data);
  const expired = () => fail(c, 400, { error: "invalid", message: "This sign-in link has expired or was already used. Request a new one." });
  if (!parsed.success) return expired();

  // Without a callbackURL Better Auth answers 200 with JSON on success, and redirects on failure.
  const res = await getAuth(c.env).api.magicLinkVerify({ query: { token: parsed.data.token }, headers: c.req.raw.headers, asResponse: true });
  if (res.status !== 200) return expired();
  forwardCookies(c, res);
  const data = (await res.json()) as { user: { id: string; email: string; emailAlerts?: boolean } };
  return c.json<Me>(me(c.env, { id: data.user.id, email: data.user.email, emailAlerts: data.user.emailAlerts !== false }));
});

account.post("/signout", async (c) => {
  if (accountsEnabled(c.env)) {
    const res = await getAuth(c.env).api.signOut({ headers: c.req.raw.headers, asResponse: true }).catch(() => null);
    if (res) forwardCookies(c, res);
  }
  return c.json({ ok: true });
});

account.patch("/account", async (c) => {
  const g = await requireWriter(c);
  if (!g.ok) return g.res;
  const body = await readJson(c);
  if (!body.ok) return body.res;
  const parsed = AccountSettingsSchema.safeParse(body.data);
  if (!parsed.success) return fail(c, 400, { error: "invalid", message: "Invalid settings." });
  await db(c.env).update(user).set({ emailAlerts: parsed.data.emailAlerts }).where(eq(user.id, g.user.id));
  return c.json<Me>(me(c.env, { ...g.user, emailAlerts: parsed.data.emailAlerts }));
});

/** Delete the account and everything tied to it (domains, alerts, push subscriptions, sessions). */
account.delete("/account", async (c) => {
  const g = await requireUser(c);
  if (!g.ok) return g.res;
  const res = await getAuth(c.env).api.signOut({ headers: c.req.raw.headers, asResponse: true }).catch(() => null);
  if (res) forwardCookies(c, res);
  await db(c.env).delete(user).where(eq(user.id, g.user.id)); // foreign keys cascade
  return c.json({ ok: true });
});

account.get("/domains", async (c) => {
  const g = await requireUser(c);
  if (!g.ok) return g.res;
  const rows = await db(c.env).select().from(domain).where(eq(domain.userId, g.user.id)).orderBy(asc(domain.createdAt));
  return c.json<DomainsResponse>({ ok: true, domains: rows.map(toSavedDomain) });
});

account.post("/domains", async (c) => {
  const g = await requireWriter(c);
  if (!g.ok) return g.res;
  const body = await readJson(c);
  if (!body.ok) return body.res;
  const parsed = SaveDomainSchema.safeParse(body.data);
  const name = parsed.success ? canonicalDomain(parsed.data.domain) : null;
  if (!name) return fail(c, 400, { error: "invalid", message: "Enter a domain name, like example.com." });

  const d = db(c.env);
  const [{ n } = { n: 0 }] = await d.select({ n: count() }).from(domain).where(eq(domain.userId, g.user.id));
  if (n >= MAX_SAVED_DOMAINS) return fail(c, 409, { error: "invalid", message: `You can save up to ${MAX_SAVED_DOMAINS} domains. Remove one to add another.` });

  const row = { id: crypto.randomUUID(), userId: g.user.id, name, verifyToken: newVerifyToken(), createdAt: new Date() };
  try {
    await d.insert(domain).values(row);
  } catch {
    return fail(c, 409, { error: "invalid", message: `${name} is already in your list.` });
  }
  const [saved] = await d.select().from(domain).where(eq(domain.id, row.id));
  return c.json({ ok: true, domain: toSavedDomain(saved!) });
});

/** Look for the TXT record now. Once found, the domain is checked daily and alerts start. */
account.post("/domains/:id/verify", async (c) => {
  const g = await requireWriter(c);
  if (!g.ok) return g.res;
  if (!(await c.env.TOKEN_LIMITER.limit({ key: `verify:${g.user.id}` })).success) return tooFast(c, "Wait a minute before checking again.");
  const d = db(c.env);
  const [row] = await d.select().from(domain).where(and(eq(domain.id, c.req.param("id")), eq(domain.userId, g.user.id)));
  if (!row) return fail(c, 404, { error: "invalid", message: "That domain isn't in your list." });

  let found: boolean;
  try {
    found = await hasVerifyRecord(new Resolver(new Budget(1)), row.name, row.verifyToken);
  } catch {
    return fail(c, 503, { error: "unavailable", message: "Couldn't look up DNS just now. Try again in a minute." });
  }
  if (!found) {
    return fail(c, 400, {
      error: "invalid",
      message: `We couldn't find the TXT record at ${row.name} yet. DNS changes can take a few minutes (sometimes longer) to show up.`,
    });
  }
  // lastCheckedAt cleared so the first daily check runs within a minute or two.
  await d.update(domain).set({ verifiedAt: new Date(), lastCheckedAt: null }).where(eq(domain.id, row.id));
  return c.json({ ok: true, domain: toSavedDomain({ ...row, verifiedAt: new Date(), lastCheckedAt: null }) });
});

account.delete("/domains/:id", async (c) => {
  const g = await requireWriter(c);
  if (!g.ok) return g.res;
  await db(c.env).delete(domain).where(and(eq(domain.id, c.req.param("id")), eq(domain.userId, g.user.id)));
  return c.json({ ok: true });
});

account.get("/alerts", async (c) => {
  const g = await requireUser(c);
  if (!g.ok) return g.res;
  const rows = await db(c.env).select().from(alert).where(eq(alert.userId, g.user.id)).orderBy(desc(alert.createdAt)).limit(HISTORY_LIMIT);
  const alerts: AlertItem[] = rows.map((r) => ({
    id: r.id,
    domain: r.domain,
    kind: r.kind,
    title: r.title,
    body: r.body,
    createdAt: r.createdAt.toISOString(),
    channel: r.deliveredAt ? r.channel : null,
  }));
  return c.json<AlertsResponse>({ ok: true, alerts });
});

/** Save this browser's push subscription. Endpoints must belong to a known push service. */
account.post("/push", async (c) => {
  const g = await requireWriter(c);
  if (!g.ok) return g.res;
  if (!vapidKeys(c.env)) return fail(c, 503, { error: "unavailable", message: "Push notifications aren't switched on yet. Alerts will come by email." });
  const body = await readJson(c);
  if (!body.ok) return body.res;
  const parsed = PushSubscriptionSchema.safeParse(body.data);
  if (!parsed.success) return fail(c, 400, { error: "invalid", message: "This browser's push service isn't supported." });
  const { endpoint, keys } = parsed.data;

  const d = db(c.env);
  // An endpoint belongs to one browser profile; if someone else signed in there before, it moves to this account.
  await d.delete(pushSubscription).where(eq(pushSubscription.endpoint, endpoint));
  await d.insert(pushSubscription).values({ id: crypto.randomUUID(), userId: g.user.id, endpoint, p256dh: keys.p256dh, auth: keys.auth, createdAt: new Date() });
  const subs = await d.select({ id: pushSubscription.id }).from(pushSubscription).where(eq(pushSubscription.userId, g.user.id)).orderBy(desc(pushSubscription.createdAt));
  const extra = subs.slice(MAX_PUSH_SUBSCRIPTIONS).map((s) => s.id);
  if (extra.length > 0) await d.delete(pushSubscription).where(inArray(pushSubscription.id, extra));
  return c.json({ ok: true });
});

account.delete("/push", async (c) => {
  const g = await requireWriter(c);
  if (!g.ok) return g.res;
  const body = await readJson(c);
  if (!body.ok) return body.res;
  const parsed = PushUnsubscribeSchema.safeParse(body.data);
  if (!parsed.success) return fail(c, 400, { error: "invalid", message: "Missing endpoint." });
  await db(c.env)
    .delete(pushSubscription)
    .where(and(eq(pushSubscription.endpoint, parsed.data.endpoint), eq(pushSubscription.userId, g.user.id)));
  return c.json({ ok: true });
});

/** Send a test notification to every device on the account. */
account.post("/push/test", async (c) => {
  const g = await requireWriter(c);
  if (!g.ok) return g.res;
  const keys = vapidKeys(c.env);
  if (!keys) return fail(c, 503, { error: "unavailable", message: "Push notifications aren't switched on yet." });
  if (!(await c.env.TOKEN_LIMITER.limit({ key: `push-test:${g.user.id}` })).success) return tooFast(c, "Wait a minute before sending another test.");
  const d = db(c.env);
  const subs = await d.select().from(pushSubscription).where(eq(pushSubscription.userId, g.user.id));
  const sent = await pushToUser(
    d,
    subs,
    { title: "Bluebench test notification", body: "Push alerts work on this device.", url: "/alerts", tag: "test" },
    keys,
    new Budget(MAX_PUSH_SUBSCRIPTIONS),
  );
  return c.json({ ok: true, sent });
});
