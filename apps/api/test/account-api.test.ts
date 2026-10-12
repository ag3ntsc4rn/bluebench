import { env, exports } from "cloudflare:workers";
import { createExecutionContext } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MAX_PUSH_SUBSCRIPTIONS, type AlertsResponse, type ApiError, type DomainsResponse, type Me, type SavedDomain } from "@bluebench/shared";
import { eq } from "drizzle-orm";
import { db } from "../src/auth.ts";
import { alert, domain, pushSubscription, session, user, verification } from "../src/db/schema.ts";
import worker from "../src/index.ts";
import { BASE, anonSession, call, cookieFrom, freshEmail, freshIp, mockServices, signIn } from "./account.ts";
import { goodDomain } from "./net.ts";

afterEach(() => vi.restoreAllMocks());

const json = async <T>(res: Response) => (await res.json()) as T;
const fcm = (n: number | string) => ({
  endpoint: `https://fcm.googleapis.com/fcm/send/device-${n}`,
  keys: { p256dh: "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4", auth: "BTBZMqHH6r4Tts7J_aSIgg" },
});

describe("GET /api/me", () => {
  it("says signed out, and that accounts are available", async () => {
    expect(await json<Me>(await call("GET", "/api/me"))).toEqual({ ok: true, signedIn: false, accountsEnabled: true });
  });

  it("reports accounts switched off when a secret is missing, without crashing", async () => {
    const off = { ...env, RESEND_API_KEY: undefined };
    const res = await worker.fetch(new Request(`${BASE}/api/me`), off, createExecutionContext());
    expect(await json<Me>(res)).toEqual({ ok: true, signedIn: false, accountsEnabled: false });
    const signin = await worker.fetch(
      new Request(`${BASE}/api/signin`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }),
      off,
      createExecutionContext(),
    );
    expect(signin.status).toBe(503);
    expect((await json<ApiError>(signin)).message).toContain("Accounts aren't switched on");
  });
});

describe("magic-link sign-in", () => {
  it("needs the bot-check session first", async () => {
    mockServices();
    const res = await call("POST", "/api/signin", { body: { email: freshEmail() }, ip: freshIp() });
    expect(res.status).toBe(401);
    expect((await json<ApiError>(res)).error).toBe("challenge");
  });

  it("emails a one-time link to the /signin page and signs in with a hardened cookie", async () => {
    const { mails } = mockServices();
    const { email, cookie, token, verified } = await signIn(mails);
    const mail = mails.at(-1)!;
    expect(mail).toMatchObject({ to: [email], from: "Bluebench <alerts@bluebench.dev>", subject: "Your Bluebench sign-in link" });
    expect(mail.text).toContain(`${BASE}/signin#token=${token}`);

    // The cookie: HttpOnly, Secure, SameSite=Strict, whole site.
    const raw = verified.headers.getSetCookie().find((c) => c.startsWith("__Secure-bb.session_token="))!;
    expect(raw).toMatch(/HttpOnly/i);
    expect(raw).toMatch(/Secure/i);
    expect(raw).toMatch(/SameSite=Strict/i);
    expect(raw).toMatch(/Path=\//i);

    const me = await json<Me>(await call("GET", "/api/me", { cookie }));
    expect(me).toEqual({ ok: true, signedIn: true, accountsEnabled: true, email, emailAlerts: true, pushKey: env.VAPID_PUBLIC_KEY });

    // No IP or user agent stored with the session; the magic-link token isn't stored in the clear.
    const d = db(env);
    const [u] = await d.select().from(user).where(eq(user.email, email));
    const sessions = await d.select().from(session).where(eq(session.userId, u!.id));
    expect(sessions).toHaveLength(1);
    expect(sessions[0]).toMatchObject({ ipAddress: null, userAgent: null });
    const pending = await d.select().from(verification);
    expect(pending.every((v) => v.identifier !== token)).toBe(true);

    // The link works once.
    const again = await call("POST", "/api/signin/verify", { body: { token }, ip: freshIp() });
    expect(again.status).toBe(400);
    expect((await json<ApiError>(again)).message).toContain("expired or was already used");
  });

  it("signs an existing account back in rather than creating another", async () => {
    const { mails } = mockServices();
    const email = freshEmail();
    await signIn(mails, email);
    await signIn(mails, email);
    expect(await db(env).select().from(user).where(eq(user.email, email))).toHaveLength(1);
  });

  it("lowercases the address and refuses junk", async () => {
    const { mails } = mockServices();
    const ip = freshIp();
    const anon = await anonSession(ip);
    expect((await call("POST", "/api/signin", { body: { email: "not-an-email" }, cookie: anon, ip })).status).toBe(400);
    expect((await call("POST", "/api/signin", { body: { email: "a@b.org", extra: 1 }, cookie: anon, ip })).status).toBe(400);
    const res = await call("POST", "/api/signin", { body: { email: "Mixed.Case@Example.ORG" }, cookie: anon, ip });
    expect(res.status).toBe(200);
    expect(mails.at(-1)!.to).toEqual(["mixed.case@example.org"]);
  });

  it("caps links per address per day", async () => {
    const { mails } = mockServices();
    const email = freshEmail();
    for (let i = 0; i < 5; i++) {
      const ip = freshIp();
      expect((await call("POST", "/api/signin", { body: { email }, cookie: await anonSession(ip), ip })).status).toBe(200);
    }
    const ip = freshIp();
    const res = await call("POST", "/api/signin", { body: { email }, cookie: await anonSession(ip), ip });
    expect(res.status).toBe(429);
    expect((await json<ApiError>(res)).error).toBe("daily-limit");
    expect(mails).toHaveLength(5);
  });

  it("says so plainly when the email can't be sent", async () => {
    mockServices({}, { resendStatus: 500 });
    const ip = freshIp();
    const res = await call("POST", "/api/signin", { body: { email: freshEmail() }, cookie: await anonSession(ip), ip });
    expect(res.status).toBe(503);
    expect((await json<ApiError>(res)).message).toContain("couldn't send the email");
  });

  it("rejects a made-up token", async () => {
    mockServices();
    const res = await call("POST", "/api/signin/verify", { body: { token: "a".repeat(32) }, ip: freshIp() });
    expect(res.status).toBe(400);
  });

  it("signs out", async () => {
    const { mails } = mockServices();
    const { cookie } = await signIn(mails);
    const res = await call("POST", "/api/signout", { cookie });
    expect(res.status).toBe(200);
    expect(cookieFrom(res, "__Secure-bb.session_token")).toBe("__Secure-bb.session_token=");
    expect(await json<Me>(await call("GET", "/api/me", { cookie }))).toMatchObject({ signedIn: false });
  });
});

describe("saved domains", () => {
  it("needs an account", async () => {
    const res = await call("GET", "/api/domains");
    expect(res.status).toBe(401);
    expect((await json<ApiError>(res)).error).toBe("signed-out");
  });

  it("adds up to 5, refuses duplicates, verifies by TXT record and removes", async () => {
    const svc = mockServices();
    const { cookie } = await signIn(svc.mails);

    const add = (d: string) => call("POST", "/api/domains", { body: { domain: d }, cookie });
    const first = await add("Example.COM."); // the page extracts domains from URLs; the API wants a name

    expect(first.status).toBe(200);
    const saved = (await json<{ domain: SavedDomain }>(first)).domain;
    expect(saved).toMatchObject({ domain: "example.com", verified: false, grade: null });
    expect(saved.verifyRecord).toMatch(/^bluebench-verify=[0-9a-f]{32}$/);

    expect((await add("example.com")).status).toBe(409);
    expect((await add("not a domain")).status).toBe(400);
    for (const d of ["b.example", "c.example", "d.example", "e.example"]) expect((await add(d)).status).toBe(200);
    const sixth = await add("f.example");
    expect(sixth.status).toBe(409);
    expect((await json<ApiError>(sixth)).message).toContain("up to 5");

    // Not published yet.
    vi.restoreAllMocks();
    mockServices({ dns: { "example.com": { TXT: ["v=spf1 -all"] } } });
    const missing = await call("POST", `/api/domains/${saved.id}/verify`, { cookie });
    expect(missing.status).toBe(400);
    expect((await json<ApiError>(missing)).message).toContain("couldn't find the TXT record");

    // Published.
    vi.restoreAllMocks();
    mockServices({ dns: { "example.com": { TXT: ["v=spf1 -all", saved.verifyRecord] } } });
    const ok = await call("POST", `/api/domains/${saved.id}/verify`, { cookie });
    expect(ok.status).toBe(200);
    expect((await json<{ domain: SavedDomain }>(ok)).domain.verified).toBe(true);

    const list = await json<DomainsResponse>(await call("GET", "/api/domains", { cookie }));
    expect(list.domains.map((d) => [d.domain, d.verified])).toEqual([
      ["example.com", true],
      ["b.example", false],
      ["c.example", false],
      ["d.example", false],
      ["e.example", false],
    ]);

    expect((await call("DELETE", `/api/domains/${saved.id}`, { cookie })).status).toBe(200);
    expect((await json<DomainsResponse>(await call("GET", "/api/domains", { cookie }))).domains).toHaveLength(4);
  });

  it("keeps each account's domains to itself", async () => {
    const svc = mockServices();
    const alice = await signIn(svc.mails);
    const bob = await signIn(svc.mails);
    const saved = (await json<{ domain: SavedDomain }>(await call("POST", "/api/domains", { body: { domain: "alice.example" }, cookie: alice.cookie }))).domain;

    expect((await json<DomainsResponse>(await call("GET", "/api/domains", { cookie: bob.cookie }))).domains).toEqual([]);
    expect((await call("POST", `/api/domains/${saved.id}/verify`, { cookie: bob.cookie })).status).toBe(404);
    await call("DELETE", `/api/domains/${saved.id}`, { cookie: bob.cookie });
    expect((await json<DomainsResponse>(await call("GET", "/api/domains", { cookie: alice.cookie }))).domains).toHaveLength(1);
  });
});

describe("push subscriptions", () => {
  it("accepts known push services only, keeps the newest 5, and sends a test", async () => {
    const svc = mockServices();
    const { cookie } = await signIn(svc.mails);

    const bad = await call("POST", "/api/push", { body: { ...fcm(0), endpoint: "https://169.254.169.254/latest" }, cookie });
    expect(bad.status).toBe(400);

    for (let i = 1; i <= MAX_PUSH_SUBSCRIPTIONS + 2; i++) {
      expect((await call("POST", "/api/push", { body: fcm(i), cookie })).status).toBe(200);
    }
    const rows = await db(env).select().from(pushSubscription);
    const mine = rows.filter((r) => r.endpoint.includes("device-"));
    expect(mine.map((r) => r.endpoint.split("-").at(-1)).sort()).toEqual(["3", "4", "5", "6", "7"]);

    const test = await call("POST", "/api/push/test", { cookie });
    expect(await json(test)).toEqual({ ok: true, sent: true });
    expect(svc.pushes).toHaveLength(5);
    expect(svc.pushes[0]!.headers.get("content-encoding")).toBe("aes128gcm");
    expect(svc.pushes[0]!.headers.get("authorization")).toMatch(/^vapid t=.+, k=/);

    expect((await call("DELETE", "/api/push", { body: { endpoint: fcm(7).endpoint }, cookie })).status).toBe(200);
    expect((await db(env).select().from(pushSubscription).where(eq(pushSubscription.endpoint, fcm(7).endpoint)))).toHaveLength(0);
  });
});

describe("account settings and deletion", () => {
  it("turns email alerts off", async () => {
    const svc = mockServices();
    const { cookie } = await signIn(svc.mails);
    const res = await call("PATCH", "/api/account", { body: { emailAlerts: false }, cookie });
    expect(await json<Me>(res)).toMatchObject({ signedIn: true, emailAlerts: false });
    expect(await json<Me>(await call("GET", "/api/me", { cookie }))).toMatchObject({ emailAlerts: false });
  });

  it("deletes the account and everything tied to it", async () => {
    const svc = mockServices();
    const { cookie, email } = await signIn(svc.mails);
    await call("POST", "/api/domains", { body: { domain: "gone.example" }, cookie });
    await call("POST", "/api/push", { body: fcm("gone"), cookie });
    const d = db(env);
    const [u] = await d.select().from(user).where(eq(user.email, email));
    await d.insert(alert).values({ id: crypto.randomUUID(), userId: u!.id, kind: "test", title: "t", body: "b", createdAt: new Date() });
    expect((await json<AlertsResponse>(await call("GET", "/api/alerts", { cookie }))).alerts).toHaveLength(1);

    const res = await call("DELETE", "/api/account", { cookie });
    expect(res.status).toBe(200);
    expect(cookieFrom(res, "__Secure-bb.session_token")).toBe("__Secure-bb.session_token=");
    for (const table of [domain, pushSubscription, alert, session] as const) {
      expect(await d.select().from(table).where(eq(table.userId, u!.id))).toHaveLength(0);
    }
    expect(await d.select().from(user).where(eq(user.email, email))).toHaveLength(0);
    expect((await call("GET", "/api/domains", { cookie })).status).toBe(401);
  });
});

describe("account writes", () => {
  it("are throttled per account (D1 has a daily write budget)", async () => {
    const svc = mockServices();
    const { cookie } = await signIn(svc.mails);
    const statuses: number[] = [];
    for (let i = 0; i < 31; i++) statuses.push((await call("PATCH", "/api/account", { body: { emailAlerts: i % 2 === 0 }, cookie })).status);
    expect(statuses.slice(0, 30).every((s) => s === 200)).toBe(true);
    expect(statuses[30]).toBe(429);
  });
});

describe("signed-in checks", () => {
  it("skip the bot check and count against the account's own cap", async () => {
    const svc = mockServices(goodDomain("signed-in.example"));
    const { cookie } = await signIn(svc.mails);
    const res = await call("POST", "/api/domain", { body: { domain: "signed-in.example" }, cookie, ip: freshIp() });
    expect(res.status).toBe(200);
  });
});

describe("cross-site requests", () => {
  it("are refused on account routes", async () => {
    const res = await exports.default.fetch(`${BASE}/api/account`, { method: "DELETE", headers: { origin: "https://evil.example" } });
    expect(res.status).toBe(403);
  });
});
