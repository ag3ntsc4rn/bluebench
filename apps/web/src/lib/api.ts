import {
  BYO_SOURCES,
  byoRequest,
  byoSourcesFor,
  parseByo,
  type ApiError,
  type ByoResponse,
  type ByoSourceId,
  type DomainReport,
  type KevResponse,
  type KevVendorsResponse,
  type KevScope,
  type LookupKind,
  type LookupResponse,
  type SourceResult,
} from "@bluebench/shared";

/** Produces a Turnstile token for a site key (runs the invisible challenge). */
export type GetTurnstileToken = (siteKey: string) => Promise<string>;

const OFFLINE: ApiError = {
  ok: false,
  error: "unavailable",
  message: "Couldn't reach Bluebench. Check your connection and try again.",
};

type Ok = { ok: true };

/** Call a JSON endpoint. Never throws: failures come back as an ApiError with a message safe to show. */
export async function requestJson<T extends Ok>(
  method: "GET" | "POST" | "PATCH" | "DELETE",
  path: string,
  body?: unknown,
  fetchImpl: typeof fetch = fetch,
): Promise<T | ApiError> {
  let res: Response;
  try {
    res = await fetchImpl(path, {
      method,
      headers: body === undefined ? {} : { "content-type": "application/json" },
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
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
export async function postWithSession<T extends Ok>(
  path: string,
  body: unknown,
  getToken: GetTurnstileToken,
  fetchImpl: typeof fetch,
): Promise<T | ApiError> {
  const first = await requestJson<T>("POST", path, body, fetchImpl);
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
  const session = await requestJson<Ok>("POST", "/api/session", { turnstileToken }, fetchImpl);
  if (!session.ok) return session;
  return requestJson<T>("POST", path, body, fetchImpl);
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

/** Ask a provider straight from the browser (OTX allows cross-site calls). No cookies, no referrer. */
async function askDirect(source: ByoSourceId, kind: LookupKind, value: string, key: string, fetchImpl: typeof fetch): Promise<SourceResult> {
  const { url, headers } = byoRequest(source, kind, value, key);
  try {
    const res = await fetchImpl(url, { headers, credentials: "omit", referrerPolicy: "no-referrer", signal: AbortSignal.timeout(8000) });
    const body: unknown = await res.json().catch(() => null);
    return { source, ...parseByo(source, kind, value, res.status, body), checkedAt: new Date().toISOString() };
  } catch {
    return { source, status: "error", summary: `Couldn't reach ${BYO_SOURCES[source].label}. Check your connection and try again.`, facts: [] };
  }
}

/**
 * Look an indicator up with the user's own keys: OTX directly from the browser, the others through
 * our relay (which needs the session the shared lookup sets up). Every source with a key that can
 * answer this kind gets a result, even if it's an error.
 */
export async function byoLookup(
  kind: LookupKind,
  value: string,
  keys: Partial<Record<ByoSourceId, string>>,
  getToken: GetTurnstileToken,
  fetchImpl: typeof fetch = fetch,
): Promise<SourceResult[]> {
  const sources = byoSourcesFor(kind, keys);
  const direct = sources.filter((s) => !BYO_SOURCES[s].relay);
  const relayed = sources.filter((s) => BYO_SOURCES[s].relay);

  const relayP: Promise<SourceResult[]> =
    relayed.length === 0
      ? Promise.resolve([])
      : postWithSession<ByoResponse>("/api/byo", { kind, value, keys: Object.fromEntries(relayed.map((s) => [s, keys[s]])) }, getToken, fetchImpl).then((res) =>
          res.ok ? res.sources : relayed.map((source) => ({ source, status: "error" as const, summary: res.message, facts: [] })),
        );
  const [d, r] = await Promise.all([Promise.all(direct.map((s) => askDirect(s, kind, value, keys[s]!, fetchImpl))), relayP]);
  const all = [...d, ...r];
  return sources.flatMap((s) => all.filter((x) => x.source === s));
}

/** Known exploited vulnerabilities: the last 90 days, or the whole catalogue. Public: no session needed. */
export const fetchKev = (scope: Exclude<KevScope, "vendors"> = "recent", fetchImpl: typeof fetch = fetch) =>
  requestJson<KevResponse>("GET", `/api/intel/kev${scope === "all" ? "?scope=all" : ""}`, undefined, fetchImpl);

/** KEV's vendor and product names (~8 KB), for the watchlist picker. */
export const fetchKevVendors = (fetchImpl: typeof fetch = fetch) => requestJson<KevVendorsResponse>("GET", "/api/intel/kev?scope=vendors", undefined, fetchImpl);
