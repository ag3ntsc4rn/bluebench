import { TURNSTILE_ORIGIN } from "@bluebench/shared";

/** Anonymous session lifetime: one Turnstile solve buys this long. */
export const SESSION_TTL_SECONDS = 24 * 60 * 60;
export const SESSION_COOKIE = "bb_session"; // sent as __Host-bb_session

const encoder = new TextEncoder();

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

/** HMAC-SHA256 of `data`, base64url. Also used to pseudonymise counter keys so raw IPs are never stored. */
export async function hmac(secret: string, data: string): Promise<string> {
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(secret), encoder.encode(data));
  return base64url(new Uint8Array(sig));
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export interface Session {
  /** Random, per-Turnstile-solve identifier. Not linked to anything else. */
  id: string;
  /** Unix seconds. */
  exp: number;
}

/** Token format: `<id>.<exp>.<sig>`, sig = HMAC(secret, "<id>.<exp>"). */
export async function signSession(secret: string, now = Date.now()): Promise<{ token: string; session: Session }> {
  const id = base64url(crypto.getRandomValues(new Uint8Array(16)));
  const exp = Math.floor(now / 1000) + SESSION_TTL_SECONDS;
  const payload = `${id}.${exp}`;
  return { token: `${payload}.${await hmac(secret, payload)}`, session: { id, exp } };
}

export async function verifySession(secret: string, token: string | undefined, now = Date.now()): Promise<Session | null> {
  if (!token) return null;
  const m = /^([A-Za-z0-9_-]{22})\.(\d{10})\.([A-Za-z0-9_-]{43})$/.exec(token);
  if (!m) return null;
  const [, id, expText, sig] = m as unknown as [string, string, string, string];
  if (!timingSafeEqual(sig, await hmac(secret, `${id}.${expText}`))) return null;
  const exp = Number(expText);
  return exp > now / 1000 ? { id, exp } : null;
}

const SITEVERIFY_URL = `${TURNSTILE_ORIGIN}/turnstile/v0/siteverify`;

/** Ask Cloudflare whether a Turnstile token is genuine. We don't send the visitor's IP. */
export async function verifyTurnstile(secret: string, token: string): Promise<boolean> {
  try {
    const body = new FormData();
    body.set("secret", secret);
    body.set("response", token);
    const res = await fetch(SITEVERIFY_URL, { method: "POST", body, signal: AbortSignal.timeout(5000) });
    if (!res.ok) return false;
    const data = (await res.json()) as { success?: unknown };
    return data.success === true;
  } catch {
    return false;
  }
}
