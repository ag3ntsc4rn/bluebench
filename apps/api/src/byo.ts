import { BYO_SOURCES, byoRequest, parseByo, RELAY_HOSTS, RELAY_SOURCE_IDS, type ByoRequest, type ByoSourceId, type LookupKind, type SourceResult } from "@bluebench/shared";

const TIMEOUT_MS = 8000;

/**
 * Ask one bring-your-own-key provider on the user's behalf. Only the fixed provider hosts can be
 * reached, redirects aren't followed, and nothing (key, indicator or answer) is logged or cached.
 */
async function ask(source: ByoSourceId, kind: LookupKind, value: string, key: string, now: number): Promise<SourceResult> {
  const label = BYO_SOURCES[source].label;
  const { url, headers } = byoRequest(source, kind, value, key);
  if (!RELAY_HOSTS.has(new URL(url).hostname)) return { source, status: "error", summary: `${label} can't be reached through Bluebench.`, facts: [] };
  try {
    const res = await fetch(url, { headers, redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_MS) });
    const body: unknown = await res.json().catch(() => null);
    return { source, ...parseByo(source, kind, value, res.status, body), checkedAt: new Date(now).toISOString() };
  } catch {
    return { source, status: "error", summary: `Couldn't reach ${label}. Try again shortly.`, facts: [] };
  }
}

/** Relay a lookup to each provider the user sent a key for that can answer this kind. `value` is canonical. */
export function relay(req: ByoRequest, value: string, now = Date.now()): Promise<SourceResult[]> {
  const sources = RELAY_SOURCE_IDS.filter((s) => req.keys[s as keyof ByoRequest["keys"]] && BYO_SOURCES[s].kinds.includes(req.kind));
  return Promise.all(sources.map((s) => ask(s, req.kind, value, req.keys[s as keyof ByoRequest["keys"]]!, now)));
}
