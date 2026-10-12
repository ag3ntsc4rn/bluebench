import { describe, expect, it } from "vitest";
import { gradeChecks, type CheckId, type CheckStatus, type DomainCheck, type DomainReport } from "@bluebench/shared";
import { certAlertDays, gradeDropAlert, hasGradedChecks, mergeStatuses, worsened } from "../src/monitor/rules.ts";

const NOW = Date.UTC(2026, 9, 11, 12);
const DAY = 86_400_000;
const at = (days: number) => new Date(NOW + days * DAY).toISOString().slice(0, 19);

function report(statuses: Partial<Record<CheckId, CheckStatus>>): DomainReport {
  const checks: DomainCheck[] = Object.entries(statuses).map(([id, status]) => ({
    id: id as CheckId,
    status: status!,
    summary: `${id} is ${status}.`,
    fix: status === "fail" ? `Fix ${id}.` : undefined,
    facts: [],
  }));
  return { ok: true, domain: "example.com", ...gradeChecks(checks), checks, checkedAt: new Date(NOW).toISOString() };
}

const ALL_PASS = { spf: "pass", dmarc: "pass", dkim: "pass", dnssec: "pass", https: "pass", hsts: "pass", headers: "pass", cert: "pass" } as const;

describe("gradeDropAlert", () => {
  it("alerts when the grade falls because a check got worse, naming the check and its fix", () => {
    const next = report({ ...ALL_PASS, dmarc: "fail" });
    const a = gradeDropAlert({ grade: "A", statuses: ALL_PASS }, next);
    expect(a?.title).toBe(`example.com: grade dropped from A to ${next.grade}`);
    expect(a?.body).toBe("DMARC: dmarc is fail. Fix: Fix dmarc.");
  });

  it("stays quiet on the first check (nothing to compare)", () => {
    expect(gradeDropAlert({ grade: null, statuses: null }, report({ ...ALL_PASS, dmarc: "fail" }))).toBeNull();
  });

  it("stays quiet when the grade holds or improves", () => {
    expect(gradeDropAlert({ grade: "A", statuses: ALL_PASS }, report({ ...ALL_PASS, headers: "warn" }))).toBeNull(); // still an A
    expect(gradeDropAlert({ grade: "C", statuses: { ...ALL_PASS, dmarc: "fail" } }, report(ALL_PASS))).toBeNull();
  });

  it("stays quiet when the grade moved only because checks were skipped", () => {
    // Skipped checks drop out of the score, so a domain with one real weakness can score lower
    // when its strong checks couldn't run. That isn't a regression.
    const prev = { ...ALL_PASS, dkim: "warn" } as const;
    const next = report({ ...prev, https: "skipped", hsts: "skipped", headers: "skipped", cert: "skipped", dnssec: "skipped" });
    expect(gradeChecks([...Object.entries(prev)].map(([id, status]) => ({ id: id as CheckId, status }))).score).toBeGreaterThan(next.score);
    expect(gradeDropAlert({ grade: "A", statuses: prev }, next)).toBeNull();
  });
});

describe("mergeStatuses / worsened", () => {
  it("remembers the last known status of a check skipped this time", () => {
    const merged = mergeStatuses({ cert: "pass", spf: "pass" }, report({ cert: "skipped", spf: "warn" }).checks);
    expect(merged).toEqual({ cert: "pass", spf: "warn" });
  });

  it("counts skipped → fail as worse only through the remembered status", () => {
    const r = report({ https: "fail", hsts: "warn", spf: "pass", mx: "info" });
    expect(worsened({ https: "pass", hsts: "warn", spf: "fail", mx: "pass" }, r.checks).map((c) => c.id)).toEqual(["https"]);
    expect(worsened({}, r.checks)).toEqual([]);
  });

  it("knows when nothing could be graded", () => {
    expect(hasGradedChecks(report({ mx: "info", spf: "skipped", cert: "skipped" }))).toBe(false);
    expect(hasGradedChecks(report({ mx: "pass", spf: "skipped" }))).toBe(false); // MX has no weight
    expect(hasGradedChecks(report({ spf: "warn" }))).toBe(true);
  });
});

describe("certAlertDays", () => {
  const yearCert = (daysLeft: number) => ({ notBefore: at(daysLeft - 365), notAfter: at(daysLeft) });

  it("walks a 1-year certificate through 30, 14 and 7 days", () => {
    expect(certAlertDays(yearCert(45), NOW)).toBeNull();
    expect(certAlertDays(yearCert(30), NOW)).toBe(30);
    expect(certAlertDays(yearCert(20), NOW)).toBe(30);
    expect(certAlertDays(yearCert(14), NOW)).toBe(14);
    expect(certAlertDays(yearCert(7), NOW)).toBe(7);
    expect(certAlertDays(yearCert(1), NOW)).toBe(7);
  });

  it("doesn't alert on a healthy 90-day certificate at 30 days left (that's when it renews)", () => {
    expect(certAlertDays({ notBefore: at(-60), notAfter: at(30) }, NOW)).toBeNull();
    expect(certAlertDays({ notBefore: at(-76), notAfter: at(14) }, NOW)).toBe(14);
  });

  it("leaves a 45-day certificate alone until 7 days left (it renews at ~15)", () => {
    expect(certAlertDays({ notBefore: at(-31), notAfter: at(14) }, NOW)).toBeNull();
    expect(certAlertDays({ notBefore: at(-38), notAfter: at(7) }, NOW)).toBe(7);
  });

  it("ignores expired certificates (the HTTPS check reports those)", () => {
    expect(certAlertDays({ notBefore: at(-400), notAfter: at(-2) }, NOW)).toBeNull();
  });
});
