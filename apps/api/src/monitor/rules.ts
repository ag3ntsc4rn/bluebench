import { CHECK_LABELS, CHECK_WEIGHTS, type CheckId, type CheckStatus, type DomainCheck, type DomainReport, type Grade } from "@bluebench/shared";
import { utc } from "../domain/cert.ts";

const DAY_MS = 86_400_000;
const GRADES: readonly Grade[] = ["A", "B", "C", "D", "F"];
/** Higher is better. info and skipped aren't graded, so they can't get "worse". */
const RANK: Partial<Record<CheckStatus, number>> = { pass: 2, warn: 1, fail: 0 };

export type Statuses = Partial<Record<CheckId, CheckStatus>>;

/**
 * Statuses to remember after a run: this run's graded results, with the previous status kept for any
 * check that was skipped this time. So a check that's skipped one day and failing the next still
 * counts as a regression from its last known result.
 */
export function mergeStatuses(prev: Statuses | null, checks: readonly Pick<DomainCheck, "id" | "status">[]): Statuses {
  const out: Statuses = { ...prev };
  for (const c of checks) if (c.status !== "skipped") out[c.id] = c.status;
  return out;
}

/** False when every weighted check was skipped (or info), so the grade means nothing this time. */
export const hasGradedChecks = (report: DomainReport) =>
  report.checks.some((c) => RANK[c.status] !== undefined && CHECK_WEIGHTS[c.id] > 0);

/** Checks whose graded status went down since the last run. */
export function worsened(prev: Statuses, checks: readonly DomainCheck[]): DomainCheck[] {
  return checks.filter((c) => {
    const before = RANK[prev[c.id] ?? "skipped"];
    const now = RANK[c.status];
    return before !== undefined && now !== undefined && now < before;
  });
}

export interface AlertText {
  title: string;
  body: string;
}

/**
 * Alert when the letter grade fell AND at least one check actually got worse. A grade can also move
 * because a check was skipped this time (crt.sh down, budget spent); that alone is never an alert.
 */
export function gradeDropAlert(prev: { grade: Grade | null; statuses: Statuses | null }, report: DomainReport): AlertText | null {
  if (!prev.grade || !prev.statuses) return null; // first check: nothing to compare with
  if (GRADES.indexOf(report.grade) <= GRADES.indexOf(prev.grade)) return null;
  const worse = worsened(prev.statuses, report.checks);
  if (worse.length === 0) return null;
  return {
    title: `${report.domain}: grade dropped from ${prev.grade} to ${report.grade}`,
    body: worse.map((c) => `${CHECK_LABELS[c.id]}: ${c.summary}${c.fix ? ` Fix: ${c.fix}` : ""}`).join("\n"),
  };
}

/** Days-left thresholds for certificate alerts. */
export const CERT_ALERT_DAYS = [30, 14, 7] as const;

/**
 * Which threshold (30/14/7 days left) a certificate has reached, or null.
 *
 * Automated certificates renew with about a third of their lifetime left (a 45-day certificate at ~15
 * days, a 90-day one at ~30). A threshold only applies once it's past that point, with a day's margin
 * for crt.sh lag and our 24-hour cache, so healthy auto-renewal never raises an alert. A 1-year
 * certificate gets all three.
 */
export function certAlertDays(cert: { notBefore: string; notAfter: string }, now: number): number | null {
  const end = utc(cert.notAfter);
  const lifetimeDays = (end - utc(cert.notBefore)) / DAY_MS;
  const left = Math.floor((end - now) / DAY_MS);
  if (!Number.isFinite(lifetimeDays) || left < 0) return null;
  const reached = CERT_ALERT_DAYS.filter((d) => d < lifetimeDays / 3 - 1 && left <= d);
  return reached.length > 0 ? Math.min(...reached) : null;
}

export function certAlert(domain: string, issuer: string, notAfter: string, days: number, now: number): AlertText {
  const left = Math.max(0, Math.floor((utc(notAfter) - now) / DAY_MS));
  return {
    title: `${domain}: certificate expires in ${left} day${left === 1 ? "" : "s"}`,
    body: `The newest certificate on record (issued by ${issuer}) expires on ${notAfter.slice(0, 10)}, under ${days} days away, and no replacement shows up in Certificate Transparency logs yet. Check that automatic renewal is working at your host or certificate provider.`,
  };
}

export function verificationLostAlert(domain: string, record: string): AlertText {
  return {
    title: `${domain}: monitoring paused`,
    body: `The TXT record ${record} is no longer published at ${domain}, so daily checks have stopped. Add it back and press Verify on the Domains page to resume.`,
  };
}
