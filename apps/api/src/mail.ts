import type { Env } from "./env.ts";

/**
 * Resend's free tier allows 100 emails a day. Magic links may use at most SIGNIN_EMAIL_DAILY_LIMIT of
 * them, so alert emails always have room; everything stops at EMAIL_DAILY_LIMIT to leave a margin.
 * Counted in the UsageCounter Durable Object.
 */
export const EMAIL_DAILY_LIMIT = 90;
export const SIGNIN_EMAIL_DAILY_LIMIT = 60;

export interface Mail {
  to: string;
  subject: string;
  /** Plain text only: no tracking pixels, no remote images. */
  text: string;
}

/** Send one email through Resend. Returns false on any failure; never throws. */
export async function sendMail(env: Env, mail: Mail): Promise<boolean> {
  if (!env.RESEND_API_KEY) return false;
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { authorization: `Bearer ${env.RESEND_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ from: env.EMAIL_FROM, to: [mail.to], subject: mail.subject, text: mail.text }),
      signal: AbortSignal.timeout(5000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/** Take one unit of today's email budget (plus the sign-in share, for magic links). */
export async function takeEmailQuota(env: Env, kind: "signin" | "alert"): Promise<boolean> {
  const usage = env.USAGE.get(env.USAGE.idFromName("daily"));
  const limits: [string, number][] = [["email:all", EMAIL_DAILY_LIMIT]];
  if (kind === "signin") limits.push(["email:signin", SIGNIN_EMAIL_DAILY_LIMIT]);
  return (await usage.consumeLimits(limits)).ok;
}
