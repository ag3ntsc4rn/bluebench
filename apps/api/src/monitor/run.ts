import { orgDomain } from "@bluebench/shared";
import { and, asc, eq, gt, isNotNull, isNull, lt, lte, ne, or } from "drizzle-orm";
import { accountsEnabled, db, type Db } from "../auth.ts";
import { alert, domain, pushSubscription, session, user, verification } from "../db/schema.ts";
import { Budget, Resolver } from "../dns.ts";
import { utc } from "../domain/cert.ts";
import { runReport } from "../domain/report.ts";
import type { Env } from "../env.ts";
import { sendMail, takeEmailQuota } from "../mail.ts";
import { sendPush, type PushMessage, type VapidKeys } from "../push.ts";
import { checkKev, pruneKevSeen } from "./kev.ts";
import { lookalikeAlert, scanLookalikes } from "./lookalike.ts";
import { runWatchdog } from "./watchdog.ts";
import { certAlert, certAlertDays, gradeDropAlert, hasGradedChecks, mergeStatuses, verificationLostAlert, type AlertText } from "./rules.ts";
import { hasVerifyRecord, verifyRecord } from "./verify.ts";

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;
/**
 * Subrequests per cron run. The free plan allows 50; D1 and Durable Object calls may count too, so a
 * re-check gets 1 for the TXT record plus 40 for the report, and a delivery run at most 40 sends.
 */
const REPORT_BUDGET = 40;
const DELIVERY_BUDGET = 40;
const PENDING_BATCH = 10;
/** A failed delivery is retried on the next runs, then given up (the alert stays in the history). */
const MAX_ATTEMPTS = 3;
/** Alert history is kept for 180 days. */
const ALERT_RETENTION_MS = 180 * DAY_MS;

export interface TickDeps {
  now?: number;
  waitUntil(p: Promise<unknown>): void;
}

export type TickResult = "off" | "delivered" | "intel" | "watchdog" | "checked" | "lookalikes" | "idle";

export function vapidKeys(env: Env): VapidKeys | null {
  if (!env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY) return null;
  return { publicKey: env.VAPID_PUBLIC_KEY, privateKey: env.VAPID_PRIVATE_KEY, subject: "mailto:security@bluebench.dev" };
}

/**
 * One cron run (every minute), one job per run to stay well inside the subrequest and CPU limits:
 * 1. deliver pending alerts, else
 * 2. re-check the domain that's most overdue (each verified domain once a day), else
 * 3. scan the next chunk of a domain's lookalikes (a full scan of ~120 names takes about 3 runs, daily).
 * At minute 30 of each hour, step 2 and 3 give way to the watchlist check (new known exploited
 * vulnerabilities against accounts' watched products), which is cheap when nothing changed, and at
 * minute 45 to the watchdog (self-tests of every outside service; ~10 subrequests).
 * A verified domain costs about 4 runs a day, so 1,440 runs cover roughly 350 domains.
 */
export async function tick(env: Env, deps: TickDeps): Promise<TickResult> {
  if (!accountsEnabled(env)) return "off";
  const now = deps.now ?? Date.now();
  const d = db(env);

  const pending = await d.select().from(alert).where(isNull(alert.deliveredAt)).orderBy(asc(alert.createdAt)).limit(PENDING_BATCH);
  if (pending.length > 0) {
    await deliverAlerts(env, d, pending, now);
    return "delivered";
  }

  const minute = new Date(now).getUTCMinutes();
  if (minute === 30) {
    await checkKev(env, d, now);
    return "intel";
  }
  if (minute === 45) {
    await runWatchdog(env, d, now);
    return "watchdog";
  }

  const [due] = await d
    .select()
    .from(domain)
    .where(and(isNotNull(domain.verifiedAt), or(isNull(domain.lastCheckedAt), lte(domain.lastCheckedAt, new Date(now - DAY_MS)))))
    .orderBy(asc(domain.lastCheckedAt))
    .limit(1);
  if (due) {
    await recheck(env, d, due, now, deps);
    return "checked";
  }

  const [scan] = await d
    .select()
    .from(domain)
    .where(
      and(
        isNotNull(domain.verifiedAt),
        or(gt(domain.lookalikeCursor, 0), isNull(domain.lookalikeScannedAt), lte(domain.lookalikeScannedAt, new Date(now - DAY_MS))),
      ),
    )
    .orderBy(asc(domain.lookalikeCheckedAt))
    .limit(1);
  if (scan) {
    await watchLookalikes(d, scan, now);
    return "lookalikes";
  }

  if (new Date(now).getUTCMinutes() === 0) await housekeeping(d, now);
  return "idle";
}

type DomainRow = typeof domain.$inferSelect;
type AlertRow = typeof alert.$inferSelect;

const newAlert = (row: DomainRow, kind: AlertRow["kind"], text: AlertText, now: number) => ({
  id: crypto.randomUUID(),
  userId: row.userId,
  domainId: row.id,
  domain: row.name,
  kind,
  title: text.title,
  body: text.body,
  createdAt: new Date(now),
});

/** Re-check one domain: confirm the TXT record is still there, run the report, raise alerts. */
export async function recheck(env: Env, d: Db, row: DomainRow, now: number, deps: TickDeps): Promise<void> {
  // Claim it first, so if anything below fails this domain can't hog every following run.
  await d.update(domain).set({ lastCheckedAt: new Date(now) }).where(eq(domain.id, row.id));

  let present: boolean;
  try {
    present = await hasVerifyRecord(new Resolver(new Budget(1)), row.name, row.verifyToken);
  } catch {
    // Couldn't ask DNS: try again in an hour rather than pausing someone's monitoring.
    await d.update(domain).set({ lastCheckedAt: new Date(now - DAY_MS + HOUR_MS) }).where(eq(domain.id, row.id));
    return;
  }
  if (!present) {
    await d.batch([
      d.update(domain).set({ verifiedAt: null }).where(eq(domain.id, row.id)),
      d.insert(alert).values(newAlert(row, "verification-lost", verificationLostAlert(row.name, verifyRecord(row.verifyToken)), now)),
    ]);
    return;
  }

  const report = await runReport(row.name, {
    env,
    tier: "user",
    waitUntil: deps.waitUntil,
    now: () => now,
    selfZone: orgDomain(new URL(env.SITE_ORIGIN).hostname),
    budget: REPORT_BUDGET,
  });

  const alerts: ReturnType<typeof newAlert>[] = [];
  const drop = gradeDropAlert({ grade: row.grade, statuses: row.statuses }, report);
  if (drop) alerts.push(newAlert(row, "grade-drop", drop, now));

  let { certExpiresAt, certAlertedDays } = row;
  const cert = report.certificate;
  if (cert) {
    const expires = new Date(utc(cert.notAfter));
    // A different certificate (renewed or replaced): its thresholds start fresh.
    if (certExpiresAt?.getTime() !== expires.getTime()) {
      certExpiresAt = expires;
      certAlertedDays = null;
    }
    const days = certAlertDays(cert, now);
    if (days !== null && (certAlertedDays === null || days < certAlertedDays)) {
      alerts.push(newAlert(row, "cert-expiry", certAlert(row.name, cert.issuer, cert.notAfter, days, now), now));
      certAlertedDays = days;
    }
  }

  // If nothing could be graded this time (an outage on our side), keep the last grade to compare against.
  const graded = hasGradedChecks(report);
  await d.batch([
    d
      .update(domain)
      .set({
        ...(graded && { grade: report.grade, score: report.score }),
        statuses: mergeStatuses(row.statuses, report.checks),
        certExpiresAt,
        certAlertedDays,
      })
      .where(eq(domain.id, row.id)),
    ...alerts.map((a) => d.insert(alert).values(a)),
  ]);
}

/** One chunk of the lookalike watcher; one alert per run listing any new lookalikes. */
export async function watchLookalikes(d: Db, row: DomainRow, now: number): Promise<void> {
  const own = await d.select({ name: domain.name }).from(domain).where(and(eq(domain.userId, row.userId), ne(domain.id, row.id)));
  const { fresh } = await scanLookalikes(d, row, now, new Set(own.map((o) => o.name)));
  if (fresh.length > 0) await d.insert(alert).values(newAlert(row, "lookalike", lookalikeAlert(row.name, fresh), now));
}

type Sub = typeof pushSubscription.$inferSelect;

/**
 * Push to every device the user subscribed. Gone subscriptions are deleted. True if any device got it.
 * Spends one unit of `budget` per send; stops when it runs out.
 */
export async function pushToUser(d: Db, subs: Sub[], msg: PushMessage, keys: VapidKeys, budget: Budget): Promise<boolean> {
  let sent = false;
  for (const sub of subs) {
    if (!budget.take()) break;
    const result = await sendPush(sub, msg, keys);
    if (result === "sent") sent = true;
    if (result === "gone") await d.delete(pushSubscription).where(eq(pushSubscription.id, sub.id));
  }
  return sent;
}

function alertEmail(env: Env, a: AlertRow): string {
  const why =
    a.kind === "kev"
      ? `You get these emails because you watch products on Bluebench's Intel tab and push notifications aren't switched on. Change your watchlist at ${env.SITE_ORIGIN}/exploited-vulnerabilities.`
      : `You get these emails because you saved ${a.domain ?? "a domain"} on Bluebench and push notifications aren't switched on.`;
  return [a.body, "", `All alerts: ${env.SITE_ORIGIN}/alerts`, "", `${why} Turn email alerts off, or delete your account, at ${env.SITE_ORIGIN}/alerts.`].join("\n");
}

/** Web Push to every device first; email only if no device got it (and the user allows email). */
async function deliverAlerts(env: Env, d: Db, pending: AlertRow[], now: number): Promise<void> {
  const budget = new Budget(DELIVERY_BUDGET);
  const keys = vapidKeys(env);
  for (const a of pending) {
    const subs = keys ? await d.select().from(pushSubscription).where(eq(pushSubscription.userId, a.userId)) : [];
    const [u] = await d.select({ email: user.email, emailAlerts: user.emailAlerts }).from(user).where(eq(user.id, a.userId));
    if (budget.max - budget.used < subs.length + (u?.emailAlerts ? 1 : 0)) break; // the rest wait for the next run

    let channel: AlertRow["channel"] = null;
    const msg: PushMessage = { title: a.title, body: a.body.slice(0, 300), url: "/alerts", tag: a.id };
    if (keys && subs.length > 0 && (await pushToUser(d, subs, msg, keys, budget))) channel = "push";
    else if (u?.emailAlerts) {
      if ((await takeEmailQuota(env, "alert")) && budget.take() && (await sendMail(env, { to: u.email, subject: a.title, text: alertEmail(env, a) }))) {
        channel = "email";
      }
    } else if (u) channel = "none"; // no device and email off: it's in the history, nothing to send

    const attempts = a.attempts + 1;
    const done = channel !== null || attempts >= MAX_ATTEMPTS;
    await d
      .update(alert)
      .set({ attempts, deliveredAt: done ? new Date(now) : null, channel: channel ?? (done ? "none" : null) })
      .where(eq(alert.id, a.id));
  }
}

/** Once an hour when there's nothing else to do: drop old alerts, expired magic links and sessions. */
async function housekeeping(d: Db, now: number): Promise<void> {
  const at = new Date(now);
  await d.batch([
    d.delete(alert).where(lt(alert.createdAt, new Date(now - ALERT_RETENTION_MS))),
    d.delete(verification).where(lt(verification.expiresAt, at)),
    d.delete(session).where(lt(session.expiresAt, at)),
    pruneKevSeen(d, now),
  ]);
}
