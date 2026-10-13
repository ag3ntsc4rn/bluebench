import type { ApiError, BatchLookupResponse, LookupResponse } from "@bluebench/shared";
import { describe, expect, it, vi } from "vitest";
import { runBulkLookup } from "./bulk";

const ok = (value: string): LookupResponse => ({ ok: true, kind: "domain", value, verdict: "not-listed", sources: [] });
const items = Array.from({ length: 12 }, (_, i) => ({ kind: "domain" as const, value: `d${i}.example` }));
const answer = (batch: { value: string }[]): BatchLookupResponse => ({ ok: true, results: batch.map((b) => ok(b.value)) });

describe("runBulkLookup", () => {
  it("sends batches of five, in order, and reports each result by index", async () => {
    const send = vi.fn(async (batch: { value: string }[]) => answer(batch));
    const seen: [number, string][] = [];
    expect(await runBulkLookup(items, { send, onResult: (i, r) => seen.push([i, r.value]) })).toBeNull();
    expect(send.mock.calls.map((c) => c[0].length)).toEqual([5, 5, 2]);
    expect(seen.map(([i]) => i)).toEqual([...Array(12).keys()]);
    expect(seen[7]).toEqual([7, "d7.example"]);
  });

  it("waits out the per-minute limit and carries on", async () => {
    const limited: ApiError = { ok: false, error: "rate-limited", message: "Slow down", retryAfter: 60 };
    const send = vi.fn().mockResolvedValueOnce(answer(items.slice(0, 5))).mockResolvedValueOnce(limited).mockImplementation(async (b) => answer(b));
    const wait = vi.fn(async () => {});
    const onPause = vi.fn();
    const seen: number[] = [];
    expect(await runBulkLookup(items, { send, wait, onPause, onResult: (i) => seen.push(i) })).toBeNull();
    expect(onPause).toHaveBeenCalledWith(60);
    expect(wait).toHaveBeenCalledWith(60_000);
    expect(seen).toHaveLength(12);
  });

  it("stops at the daily cap, keeping what came back", async () => {
    const send = vi.fn(async (batch: { value: string }[]): Promise<BatchLookupResponse> => ({
      ok: true,
      results: [ok(batch[0]!.value), ...batch.slice(1).map((b) => ({ ok: false as const, kind: "domain" as const, value: b.value, error: "daily-limit" as const, message: "Used up" }))],
    }));
    const seen: number[] = [];
    const stop = await runBulkLookup(items, { send, onResult: (i) => seen.push(i) });
    expect(stop).toMatchObject({ error: "daily-limit", message: "Used up" });
    expect(send).toHaveBeenCalledTimes(1);
    expect(seen).toEqual([0, 1, 2, 3, 4]);
  });

  it("stops on any other error", async () => {
    const send = vi.fn(async (): Promise<ApiError> => ({ ok: false, error: "challenge", message: "Bot check failed" }));
    expect(await runBulkLookup(items, { send, onResult: () => {} })).toMatchObject({ error: "challenge" });
    expect(send).toHaveBeenCalledTimes(1);
  });
});
