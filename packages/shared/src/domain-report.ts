import { z } from "zod";
import { normalizeDomain } from "./domain.ts";
import { parseIp } from "./ip.ts";

export const DomainRequestSchema = z.strictObject({
  domain: z.string().min(1).max(253),
});
export type DomainRequest = z.infer<typeof DomainRequestSchema>;

/** Normalized public hostname, or null. IP literals are refused: there's no DNS to grade. */
export function canonicalDomain(input: string): string | null {
  const host = input.trim().replace(/\.$/, "");
  if (parseIp(host.replace(/^\[(.*)\]$/, "$1"))) return null;
  return normalizeDomain(host);
}

export type CheckId = "mx" | "spf" | "dmarc" | "dkim" | "dnssec" | "https" | "hsts" | "headers" | "cert";

export const CHECK_LABELS: Readonly<Record<CheckId, string>> = {
  mx: "Mail servers (MX)",
  spf: "SPF",
  dmarc: "DMARC",
  dkim: "DKIM",
  dnssec: "DNSSEC",
  https: "HTTPS",
  hsts: "HSTS",
  headers: "Security headers",
  cert: "Certificate",
};

/**
 * pass / warn / fail count toward the grade. info is shown but not graded (e.g. "doesn't receive
 * email"). skipped means we couldn't check it this time, so it isn't graded either.
 */
export type CheckStatus = "pass" | "warn" | "fail" | "info" | "skipped";

export interface DomainCheck {
  id: CheckId;
  status: CheckStatus;
  /** One plain-English line. */
  summary: string;
  /** One-line fix, when there's something to do. */
  fix?: string;
  facts: { label: string; value: string }[];
}

export type Grade = "A" | "B" | "C" | "D" | "F";

export interface DomainReport {
  ok: true;
  domain: string;
  grade: Grade;
  /** 0–100, over the checks that were graded. */
  score: number;
  checks: DomainCheck[];
  /** ISO time the checks ran. */
  checkedAt: string;
  /** True when served from the 1-hour report cache. */
  cached?: boolean;
}

/** Points per check. Ungraded checks (info, skipped) drop out of the total. */
export const CHECK_WEIGHTS: Readonly<Record<CheckId, number>> = {
  mx: 0,
  spf: 15,
  dmarc: 20,
  dkim: 10,
  dnssec: 10,
  https: 15,
  hsts: 10,
  headers: 10,
  cert: 10,
};

const CREDIT: Partial<Record<CheckStatus, number>> = { pass: 1, warn: 0.5, fail: 0 };

export function gradeChecks(checks: readonly Pick<DomainCheck, "id" | "status">[]): { score: number; grade: Grade } {
  let earned = 0;
  let possible = 0;
  for (const c of checks) {
    const credit = CREDIT[c.status];
    const weight = CHECK_WEIGHTS[c.id];
    if (credit === undefined || weight === 0) continue;
    earned += credit * weight;
    possible += weight;
  }
  const score = possible === 0 ? 0 : Math.round((earned / possible) * 100);
  const grade: Grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  return { score, grade };
}
