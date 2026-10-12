import { betterAuth } from "better-auth/minimal";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { magicLink } from "better-auth/plugins/magic-link";
import { drizzle } from "drizzle-orm/d1";
import * as schema from "./db/schema.ts";
import type { Env } from "./env.ts";
import { sendMail } from "./mail.ts";

export const db = (env: Env) => drizzle(env.DB, { schema });
export type Db = ReturnType<typeof db>;

/** Magic links work for 15 minutes (email can be slow), once. */
const MAGIC_LINK_TTL_S = 15 * 60;
const SESSION_TTL_S = 30 * 24 * 3600;

/** Accounts need a database, a signing secret and a way to send the magic link. */
export const accountsEnabled = (env: Env) => Boolean(env.BETTER_AUTH_SECRET && env.RESEND_API_KEY && env.DB);

function magicLinkEmail(url: string): string {
  return [
    "Here's your link to sign in to Bluebench:",
    "",
    url,
    "",
    "It works once, for the next 15 minutes. If you didn't ask for it, ignore this email: nothing happens unless the link is opened.",
    "",
    "Bluebench, the free security toolkit",
  ].join("\n");
}

function createAuth(env: Env) {
  return betterAuth({
    appName: "Bluebench",
    baseURL: env.SITE_ORIGIN,
    // Never mounted: our own routes in account.ts call auth.api directly, so only what we choose is exposed.
    basePath: "/api/auth",
    secret: env.BETTER_AUTH_SECRET,
    trustedOrigins: [env.SITE_ORIGIN],
    database: drizzleAdapter(db(env), { provider: "sqlite", schema }),
    session: { expiresIn: SESSION_TTL_S, updateAge: 24 * 3600 },
    user: { additionalFields: { emailAlerts: { type: "boolean", defaultValue: true, input: false } } },
    // We rate-limit in our own routes (Turnstile, per-IP, per-email and the email budget).
    rateLimit: { enabled: false },
    telemetry: { enabled: false },
    advanced: {
      useSecureCookies: true,
      cookiePrefix: "bb",
      defaultCookieAttributes: { httpOnly: true, secure: true, sameSite: "strict", path: "/" },
      ipAddress: { disableIpTracking: true },
    },
    databaseHooks: {
      // Better Auth records the user agent and IP on each session; we don't keep either.
      session: { create: { before: async (s) => ({ data: { ...s, ipAddress: null, userAgent: null } }) } },
    },
    plugins: [
      magicLink({
        expiresIn: MAGIC_LINK_TTL_S,
        storeToken: "hashed",
        // The link opens a page that asks for a click before using the token, so mail scanners that
        // fetch links can't burn it. The token is in the fragment, so it never reaches a server log.
        sendMagicLink: async ({ email, token }) => {
          const url = `${env.SITE_ORIGIN}/signin#token=${token}`;
          const sent = await sendMail(env, { to: email, subject: "Your Bluebench sign-in link", text: magicLinkEmail(url) });
          if (!sent) throw new MailFailed();
        },
      }),
    ],
  });
}

export class MailFailed extends Error {}

export type Auth = ReturnType<typeof createAuth>;

const cache = new WeakMap<Env, Auth>();

/** One Better Auth instance per isolate (per env object): building it is the expensive part. */
export function getAuth(env: Env): Auth {
  let auth = cache.get(env);
  if (!auth) {
    auth = createAuth(env);
    cache.set(env, auth);
  }
  return auth;
}

/** Name of the account session cookie, as Better Auth sets it. Used to skip the DB when it's absent. */
export const AUTH_COOKIE = "__Secure-bb.session_token";

export interface AccountUser {
  id: string;
  email: string;
  emailAlerts: boolean;
}

/** The signed-in user for a request, or null. Only touches the database when the cookie is present. */
export async function currentUser(env: Env, headers: Headers): Promise<AccountUser | null> {
  if (!accountsEnabled(env) || !headers.get("cookie")?.includes(AUTH_COOKIE)) return null;
  try {
    const s = await getAuth(env).api.getSession({ headers });
    return s && { id: s.user.id, email: s.user.email, emailAlerts: s.user.emailAlerts !== false };
  } catch {
    return null;
  }
}
