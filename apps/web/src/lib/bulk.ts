import { LOOKUP_BATCH_SIZE, type ApiError, type BatchLookupResponse, type LookupKind } from "@bluebench/shared";

type Item = { kind: LookupKind; value: string };
type Result = BatchLookupResponse["results"][number];

export interface BulkDeps {
  send: (batch: Item[]) => Promise<BatchLookupResponse | ApiError>;
  /** Called with each item's result, by its index in `items`. */
  onResult: (index: number, result: Result) => void;
  /** The per-minute limit was hit: waiting this many seconds before carrying on. */
  onPause?: (seconds: number) => void;
  wait?: (ms: number) => Promise<void>;
}

/** Pauses for the per-minute limit before giving up on a batch. */
const MAX_PAUSES = 3;

/**
 * Look items up in batches, in order. Waits out the per-minute limit and carries on; stops at the
 * daily cap or any other error, returning it. Items after a stop simply get no result.
 */
export async function runBulkLookup(items: readonly Item[], deps: BulkDeps): Promise<ApiError | null> {
  const wait = deps.wait ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  for (let start = 0; start < items.length; start += LOOKUP_BATCH_SIZE) {
    const batch = items.slice(start, start + LOOKUP_BATCH_SIZE);
    let res = await deps.send(batch);
    for (let pauses = 0; !res.ok && res.error === "rate-limited" && pauses < MAX_PAUSES; pauses++) {
      const seconds = res.retryAfter ?? 60;
      deps.onPause?.(seconds);
      await wait(seconds * 1000);
      res = await deps.send(batch);
    }
    if (!res.ok) return res;
    res.results.forEach((r, i) => deps.onResult(start + i, r));
    const capped = res.results.find((r): r is Extract<Result, { ok: false }> => !r.ok && r.error === "daily-limit");
    if (capped) return { ok: false, error: "daily-limit", message: capped.message };
  }
  return null;
}
