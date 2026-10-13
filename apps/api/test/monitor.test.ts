import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { CheckId, CheckStatus } from "@bluebench/shared";
import { eq } from "drizzle-orm";
import { db } from "../src/auth.ts";
import { alert, domain, pushSubscription, user } from "../src/db/schema.ts";
import { recheck, tick } from "../src/monitor/run.ts";
import { freshEmail, mockServices } from "./account.ts";
import { goodDomain, type FakeNet } from "./net.ts";

afterEach(() => vi.restoreAllMocks());

const DAY = 86_400_000;
const NOW = Date.now();
const TOKEN = "0123456789abcdef0123456789abcdef";
const RECORD = `bluebench-verify=${TOKEN}`;
let n = 0;
const uniq = () => `monitored${n++}-${NOW}.test`;
const d = () => db(env);
const ALL_PASS: Partial<Record<CheckId, CheckStatus>> = {
  mx: "pass",
  spf: "pass",
  dmarc: "pass",
  dkim: "pass",
  dnssec: "pass",
  https: "pass",
  hsts: "pass",
  headers: "pass",
  cert: "pass",
};

/**
 * Report tests use a quota stub that always grants (the real crt.sh quota is 5/min); quota behaviour
 * is covered in quota.test.ts. KV writes from waitUntil are collected and awaited.
 */
const openQuota = {
  idFromName: () => ({}),
  get: () => ({ acquire: async () => ({ ok: true }) }),
} as unknown as typeof env.PROVIDER_QUOTA;
const testEnv = { ...env, PROVIDER_QUOTA: openQuota };
const later: Promise<unknown>[] = [];
const deps = (now = NOW) => ({ now, waitUntil: (p: Promise<unknown>) => void later.push(p) });

/** A good domain with our TXT record published. */
function verifiedGood(name: string): FakeNet {
  const net = goodDomain(name);
  net.dns![name]!.TXT = [...net.dns![name]!.TXT!, RECORD];
  return net;
}

async function seed(name: string, row: Partial<typeof domain.$inferInsert> = {}, opts: { emailAlerts?: boolean } = {}) {
  const userId = crypto.randomUUID();
  const email = freshEmail();
  const t = new Date(NOW - 30 * DAY);
  await d().insert(user).values({ id: userId, name: "", email, emailVerified: true, createdAt: t, updatedAt: t, emailAlerts: opts.emailAlerts ?? true });
  const id = crypto.randomUUID();
  await d().insert(domain).values({ id, userId, name, verifyToken: TOKEN, verifiedAt: t, createdAt: t, ...row });
  const [saved] = await d().select().from(domain).where(eq(domain.id, id));
  return { row: saved!, userId, email };
}

const fetchRow = async (id: string) => (await d().select().from(domain).where(eq(domain.id, id)))[0]!;
const alertsFor = (userId: string) => d().select().from(alert).where(eq(alert.userId, userId));

describe("recheck", () => {
  it("records a baseline on the first check, without alerting", async () => {
    const name = uniq();
    mockServices(verifiedGood(name));
    const { row, userId } = await seed(name);
    await recheck(testEnv, d(), row, NOW, deps());

    const after = await fetchRow(row.id);
    expect(after).toMatchObject({ grade: "A", score: 100, certAlertedDays: null });
    expect(after.statuses).toMatchObject({ spf: "pass", dmarc: "pass", cert: "pass" });
    expect(after.lastCheckedAt?.getTime()).toBe(NOW);
    expect(Math.round((after.certExpiresAt!.getTime() - NOW) / DAY)).toBe(80);
    expect(await alertsFor(userId)).toEqual([]);
  });

  it("raises one grade-drop alert naming what broke", async () => {
    const name = uniq();
    const net = verifiedGood(name);
    delete net.dns![`_dmarc.${name}`];
    delete net.sites![`https://${name}/`]!.headers!["strict-transport-security"];
    mockServices(net);
    const { row, userId } = await seed(name, { grade: "A", score: 100, statuses: ALL_PASS });
    await recheck(testEnv, d(), row, NOW, deps());

    const alerts = await alertsFor(userId);
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({ kind: "grade-drop", domain: name, domainId: row.id, deliveredAt: null });
    expect(alerts[0]!.title).toMatch(new RegExp(`^${name.replace(/\./g, "\\.")}: grade dropped from A to [B-F]$`));
    expect(alerts[0]!.body).toContain("DMARC:");
    expect(alerts[0]!.body).toContain("HSTS:");
  });

  it("doesn't alert when crt.sh is down (skipped isn't worse), and keeps the cert's last status", async () => {
    const name = uniq();
    mockServices({ ...verifiedGood(name), crtsh: 502 });
    const { row, userId } = await seed(name, { grade: "A", score: 100, statuses: ALL_PASS });
    await recheck(testEnv, d(), row, NOW, deps());
    expect(await alertsFor(userId)).toEqual([]);
    expect((await fetchRow(row.id)).statuses?.cert).toBe("pass");
  });

  it("pauses monitoring and says so when the TXT record is gone", async () => {
    const name = uniq();
    mockServices(goodDomain(name)); // no verify record
    const { row, userId } = await seed(name, { grade: "A", statuses: ALL_PASS });
    await recheck(testEnv, d(), row, NOW, deps());

    expect((await fetchRow(row.id)).verifiedAt).toBeNull();
    const alerts = await alertsFor(userId);
    expect(alerts.map((a) => a.kind)).toEqual(["verification-lost"]);
    expect(alerts[0]!.body).toContain(RECORD);
  });

  it("retries in an hour when DNS fails, rather than pausing monitoring", async () => {
    const name = uniq();
    mockServices({ dns: { [name]: { servfail: true } } });
    const { row, userId } = await seed(name);
    await recheck(testEnv, d(), row, NOW, deps());

    const after = await fetchRow(row.id);
    expect(after.verifiedAt).not.toBeNull();
    expect(after.lastCheckedAt!.getTime()).toBe(NOW - DAY + 3_600_000);
    expect(await alertsFor(userId)).toEqual([]);
  });

  it("alerts on a 1-year certificate at 30 days, then at 14, once each", async () => {
    const name = uniq();
    const iso = (t: number) => new Date(t).toISOString().slice(0, 19);
    const notAfter = NOW + 20 * DAY + 3_600_000;
    const net = verifiedGood(name);
    net.crtsh = [{ issuer_name: "C=US, O=Example CA, CN=Example CA 1", name_value: name, not_before: iso(notAfter - 365 * DAY), not_after: iso(notAfter) }];
    mockServices(net);
    const { row, userId } = await seed(name);

    await recheck(testEnv, d(), row, NOW, deps());
    let alerts = await alertsFor(userId);
    expect(alerts.map((a) => a.kind)).toEqual(["cert-expiry"]);
    expect(alerts[0]!.title).toBe(`${name}: certificate expires in 20 days`);
    expect(alerts[0]!.body).toContain("Example CA");
    expect((await fetchRow(row.id)).certAlertedDays).toBe(30);

    // Next day: same threshold, no repeat.
    await recheck(testEnv, d(), await fetchRow(row.id), NOW + DAY, deps(NOW + DAY));
    expect(await alertsFor(userId)).toHaveLength(1);

    // A week later: under 14 days.
    await recheck(testEnv, d(), await fetchRow(row.id), NOW + 7 * DAY, deps(NOW + 7 * DAY));
    alerts = await alertsFor(userId);
    expect(alerts).toHaveLength(2);
    expect((await fetchRow(row.id)).certAlertedDays).toBe(14);
  });

  it("starts the thresholds again for a renewed certificate", async () => {
    const name = uniq();
    mockServices(verifiedGood(name)); // newest cert has 80 days left
    const { row } = await seed(name, { certExpiresAt: new Date(NOW + 3 * DAY), certAlertedDays: 7 });
    await recheck(testEnv, d(), row, NOW, deps());
    expect((await fetchRow(row.id)).certAlertedDays).toBeNull();
  });
});

describe("tick", () => {
  /** Alerts and domains from other tests may exist; run a few ticks until ours has been handled. */
  async function tickUntil(done: () => Promise<boolean>, now = NOW) {
    // Minute 30 of each hour belongs to the watchlist check (kev.test.ts); step past it.
    if (new Date(now).getUTCMinutes() === 30) now += 60_000;
    for (let i = 0; i < 10 && !(await done()); i++) await tick(testEnv, deps(now));
    expect(await done()).toBe(true);
  }

  it("re-checks a verified domain that's due, and leaves one checked recently alone", async () => {
    const name = uniq();
    mockServices(verifiedGood(name));
    const due = await seed(name, { lastCheckedAt: new Date(NOW - DAY - 1000) });
    const fresh = await seed(uniq(), { lastCheckedAt: new Date(NOW - 3_600_000) });
    const unverified = await seed(uniq(), { verifiedAt: null });

    await tickUntil(async () => (await fetchRow(due.row.id)).grade === "A");
    expect((await fetchRow(fresh.row.id)).lastCheckedAt!.getTime()).toBe(NOW - 3_600_000);
    expect((await fetchRow(unverified.row.id)).lastCheckedAt).toBeNull();
  });

  async function pendingAlert(userId: string) {
    const id = crypto.randomUUID();
    // Oldest first, so it's in the first batch whatever else is pending.
    await d().insert(alert).values({ id, userId, domain: "example.com", kind: "grade-drop", title: "example.com: grade dropped from A to C", body: "DMARC: missing.", createdAt: new Date(1000) });
    return id;
  }
  const alertRow = async (id: string) => (await d().select().from(alert).where(eq(alert.id, id)))[0]!;

  it("delivers a pending alert by push, encrypted, to every device", async () => {
    const svc = mockServices();
    const { userId } = await seed(uniq());
    for (const i of [1, 2]) {
      await d().insert(pushSubscription).values({
        id: crypto.randomUUID(),
        userId,
        endpoint: `https://fcm.googleapis.com/fcm/send/monitor-${userId}-${i}`,
        p256dh: "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
        auth: "BTBZMqHH6r4Tts7J_aSIgg",
        createdAt: new Date(),
      });
    }
    const id = await pendingAlert(userId);
    await tickUntil(async () => (await alertRow(id)).deliveredAt !== null);

    expect(await alertRow(id)).toMatchObject({ channel: "push", attempts: 1 });
    const mine = svc.pushes.filter((p) => p.url.includes(userId));
    expect(mine).toHaveLength(2);
    expect(mine[0]!.headers.get("content-encoding")).toBe("aes128gcm");
    // Encrypted: the alert text isn't in the body.
    expect(new TextDecoder().decode(mine[0]!.body)).not.toContain("DMARC");
    expect(svc.mails.filter((m) => m.subject.includes("grade dropped"))).toHaveLength(0);
  });

  it("drops a subscription the push service says is gone, and falls back to email", async () => {
    const svc = mockServices({}, { pushStatus: 410 });
    const { userId, email } = await seed(uniq());
    await d().insert(pushSubscription).values({
      id: crypto.randomUUID(),
      userId,
      endpoint: `https://updates.push.services.mozilla.com/wpush/v2/${userId}`,
      p256dh: "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
      auth: "BTBZMqHH6r4Tts7J_aSIgg",
      createdAt: new Date(),
    });
    const id = await pendingAlert(userId);
    await tickUntil(async () => (await alertRow(id)).deliveredAt !== null);

    expect((await alertRow(id)).channel).toBe("email");
    expect(await d().select().from(pushSubscription).where(eq(pushSubscription.userId, userId))).toEqual([]);
    const mail = svc.mails.find((m) => m.to[0] === email)!;
    expect(mail.subject).toBe("example.com: grade dropped from A to C");
    expect(mail.text).toContain("DMARC: missing.");
    expect(mail.text).toContain("https://bluebench.dev/alerts");
  });

  it("keeps the alert in the history without sending anything when email is off and there's no device", async () => {
    const svc = mockServices();
    const { userId, email } = await seed(uniq(), {}, { emailAlerts: false });
    const id = await pendingAlert(userId);
    await tickUntil(async () => (await alertRow(id)).deliveredAt !== null);
    expect((await alertRow(id)).channel).toBe("none");
    expect(svc.mails.filter((m) => m.to[0] === email)).toEqual([]);
  });

  it("gives up after 3 failed attempts", async () => {
    mockServices({}, { resendStatus: 500 });
    const { userId } = await seed(uniq());
    const id = await pendingAlert(userId);
    await tickUntil(async () => (await alertRow(id)).deliveredAt !== null);
    expect(await alertRow(id)).toMatchObject({ attempts: 3, channel: "none" });
  });

  it("does nothing when accounts aren't configured", async () => {
    expect(await tick({ ...testEnv, BETTER_AUTH_SECRET: undefined }, deps())).toBe("off");
  });
});
