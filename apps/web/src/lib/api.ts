import type { ApiError, LookupKind, LookupResponse } from "@bluebench/shared";

/** Produces a Turnstile token for a site key (runs the invisible challenge). */
export type GetTurnstileToken = (siteKey: string) => Promise<string>;

const OFFLINE: ApiError = {
  ok: false,
  error: "unavailable",
  message: "Couldn't reach Bluebench. Check your connection and try again.",
};

async function postJson(path: string, body: unknown, fetchImpl: typeof fetch): Promise<LookupResponse | ApiError | { ok: true }> {
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
    const data = (await res.json()) as LookupResponse | ApiError | { ok: true };
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
 * Look up an indicator's reputation. Runs the bot check only when the server asks for it
 * (first lookup, or after the 24 h session expires), then retries once.
 */
export async function lookupReputation(
  kind: LookupKind,
  value: string,
  getToken: GetTurnstileToken,
  fetchImpl: typeof fetch = fetch,
): Promise<LookupResponse | ApiError> {
  const first = await postJson("/api/lookup", { kind, value }, fetchImpl);
  if (first.ok || first.error !== "challenge" || !first.siteKey) return first as LookupResponse | ApiError;

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
  const session = await postJson("/api/session", { turnstileToken }, fetchImpl);
  if (!session.ok) return session;
  return (await postJson("/api/lookup", { kind, value }, fetchImpl)) as LookupResponse | ApiError;
}
