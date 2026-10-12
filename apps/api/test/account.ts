import { exports } from "cloudflare:workers";
import { expect } from "vitest";
import { mockNet, type FakeNet } from "./net.ts";

export const BASE = "https://bluebench.dev";
let ipCounter = 1;
/** Each client gets its own IP so per-IP rate limits don't leak between tests. */
export const freshIp = () => `203.0.113.${ipCounter++ % 250}`;
let emailCounter = 0;
export const freshEmail = () => `person${emailCounter++}-${Date.now()}@example.org`;

export function call(method: string, path: string, opts: { body?: unknown; cookie?: string; ip?: string } = {}) {
  const headers: Record<string, string> = { "cf-connecting-ip": opts.ip ?? "203.0.113.254", origin: BASE };
  if (opts.cookie) headers.cookie = opts.cookie;
  if (opts.body !== undefined) headers["content-type"] = "application/json";
  return exports.default.fetch(`${BASE}${path}`, {
    method,
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });
}

export interface SentMail {
  to: string[];
  from: string;
  subject: string;
  text: string;
}

/**
 * Fake network: DoH/sites/crt.sh from `net`, plus Turnstile, Resend (emails are captured) and push
 * services (answer with `pushStatus`, default 201). Returns the logs.
 */
export function mockServices(net: FakeNet = {}, opts: { pushStatus?: number; resendStatus?: number } = {}) {
  const mails: SentMail[] = [];
  const pushes: { url: string; headers: Headers; body: Uint8Array }[] = [];
  const calls = mockNet({
    ...net,
    handle: async (req, url) => {
      if (url.hostname === "api.resend.com") {
        expect(req.headers.get("authorization")).toBe("Bearer test-resend-key");
        mails.push((await req.json()) as SentMail);
        return new Response(JSON.stringify({ id: "x" }), { status: opts.resendStatus ?? 200 });
      }
      if (url.hostname === "fcm.googleapis.com" || url.hostname === "updates.push.services.mozilla.com") {
        pushes.push({ url: url.href, headers: req.headers, body: new Uint8Array(await req.arrayBuffer()) });
        return new Response(null, { status: opts.pushStatus ?? 201 });
      }
      return net.handle?.(req, url);
    },
  });
  return { mails, pushes, calls };
}

export const tokenFrom = (mail: SentMail) => /\/signin#token=([A-Za-z0-9_-]+)/.exec(mail.text)?.[1];

export function cookieFrom(res: Response, name: string): string | undefined {
  return res.headers
    .getSetCookie()
    .find((c) => c.startsWith(`${name}=`))
    ?.split(";")[0];
}

/** An anonymous bot-check session cookie, as the browser gets after Turnstile. */
export async function anonSession(ip: string): Promise<string> {
  const res = await call("POST", "/api/session", { body: { turnstileToken: "good-token" }, ip });
  expect(res.status).toBe(200);
  return cookieFrom(res, "__Host-bb_session")!;
}

/** Sign in end to end (bot check, magic link email, verify) and return the account cookie. Needs mockServices(). */
export async function signIn(mails: SentMail[], email = freshEmail()) {
  const ip = freshIp();
  const anon = await anonSession(ip);
  const before = mails.length;
  const res = await call("POST", "/api/signin", { body: { email }, cookie: anon, ip });
  expect(res.status, await res.clone().text()).toBe(200);
  expect(mails.length).toBe(before + 1);
  const token = tokenFrom(mails.at(-1)!)!;
  const verified = await call("POST", "/api/signin/verify", { body: { token }, ip });
  expect(verified.status, await verified.clone().text()).toBe(200);
  const cookie = cookieFrom(verified, "__Secure-bb.session_token");
  expect(cookie).toBeTruthy();
  return { email, ip, cookie: cookie!, token, verified };
}
