import type { Grade } from "@bluebench/shared";
import { and, desc, eq, isNotNull } from "drizzle-orm";
import { accountsEnabled, db } from "./auth.ts";
import { domain } from "./db/schema.ts";
import type { Env } from "./env.ts";

/**
 * Grade badges for READMEs and site footers: /api/badge/<domain>.svg. Only for domains whose owner
 * verified them and chose to publish the badge; the grade is the daily monitoring check's, so a badge
 * view never runs a check. Anything else gets a neutral "not public" badge (still an image, so the
 * page embedding it doesn't show a broken one).
 */

/** Status colours from the design (OK sky blue, warning amber, critical coral), with the dark text that reads on them. */
const GRADE_FILL: Readonly<Record<Grade, string>> = { A: "#6CB4FF", B: "#6CB4FF", C: "#F5A524", D: "#FF8A6B", F: "#FF8A6B" };

export async function publicGrade(env: Env, name: string): Promise<Grade | null> {
  if (!accountsEnabled(env)) return null;
  const [row] = await db(env)
    .select({ grade: domain.grade })
    .from(domain)
    .where(and(eq(domain.name, name), eq(domain.badgePublic, true), isNotNull(domain.verifiedAt), isNotNull(domain.grade)))
    .orderBy(desc(domain.lastCheckedAt))
    .limit(1);
  return row?.grade ?? null;
}

/** A flat two-part badge. Fixed widths: the right part is a single letter or the fixed "not public". */
export function badgeSvg(grade: Grade | null): string {
  const left = 70;
  const right = grade ? 26 : 66;
  const width = left + right;
  const label = grade ? `Bluebench grade: ${grade}` : "Bluebench grade: not public";
  const fill = grade ? GRADE_FILL[grade] : "#262C36";
  const ink = grade ? "#050B18" : "#E8EAED";
  const value = grade ?? "not public";
  return [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20" role="img" aria-label="${label}">`,
    `<title>${label}</title>`,
    `<rect width="${left}" height="20" fill="#171B22"/>`,
    `<rect x="${left}" width="${right}" height="20" fill="${fill}"/>`,
    `<g font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">`,
    `<text x="${left / 2}" y="14" fill="#E8EAED">Bluebench</text>`,
    `<text x="${left + right / 2}" y="14" fill="${ink}" font-weight="bold">${value}</text>`,
    `</g></svg>`,
  ].join("");
}

export const BADGE_CACHE_SECONDS = 3600;
