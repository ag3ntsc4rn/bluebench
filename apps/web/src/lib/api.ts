import type { ApiError, DomainReport, LookupKind, LookupResponse } from "@bluebench/shared";

/** Produces a Turnstile token for a site key (runs the invisible challenge). */
export type GetTurnstileToken = (siteKey: string) => Promise<string>;

const OFFLINE: ApiError = {
  ok: false,
  error: "unavailable",
  message: "Couldn't reach Bluebench. Check your connection and try again.",
};

type Ok = { ok: true };

async function postJson<T extends Ok>(path: string, body: unknown, fetchImpl: typeof fetch): Promise<T | ApiError> {
  let res: Response;
  try {
    res = await fetchImpl(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body),
    });
  } catch {
    return OFFLINE;
  }
  try {
    const data = (await res.json()) as T | ApiError;
    if (typeof data === "object" && data !== null && "ok" in data) {
      // Unknown server errors carry a bare string; never show those raw.
      if (!data.ok && !("message" in data)) return { ok: false, error: "unavailable", message: "Something went wrong on our side. Try again shortly." };
      return data;
    }
  } catch {
    // fall through
  }
  return { ok: false, error: "unavailable", message: "Something went wrong on our side. Try again shortly." };
}

/**
 * POST to an endpoint that needs a session. Runs the bot check only when the server asks for it
 * (first use, or after the 24 h session expires), then retries once.
 */
async function postWithSession<T extends Ok>(
  path: string,
  body: unknown,
  getToken: GetTurnstileToken,
  fetchImpl: typeof fetch,
): Promise<T | ApiError> {
  const first = await postJson<T>(path, body, fetchImpl);
  if (first.ok || first.error !== "challenge" || !first.siteKey) return first;

  let turnstileToken: string;
  try {
    turnstileToken = await getToken(first.siteKey);
  } catch {
    return {
      ok: false,
      error: "challenge",
      message: "The bot check couldn't run. If you block challenges.cloudflare.com, lookups won't work, but the browser tools still do.",
    };
  }
  const session = await postJson<Ok>("/api/session", { turnstileToken }, fetchImpl);
  if (!session.ok) return session;
  return postJson<T>(path, body, fetchImpl);
}

/** Look up an indicator's reputation. */
export function lookupReputation(
  kind: LookupKind,
  value: string,
  getToken: GetTurnstileToken,
  fetchImpl: typeof fetch = fetch,
): Promise<LookupResponse | ApiError> {
  return postWithSession<LookupResponse>("/api/lookup", { kind, value }, getToken, fetchImpl);
}

/** Grade a domain's email and web security. */
export function checkDomain(domain: string, getToken: GetTurnstileToken, fetchImpl: typeof fetch = fetch): Promise<DomainReport | ApiError> {
  return postWithSession<DomainReport>("/api/domain", { domain }, getToken, fetchImpl);
}
