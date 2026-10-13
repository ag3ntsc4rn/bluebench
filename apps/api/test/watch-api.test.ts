import { afterEach, describe, expect, it, vi } from "vitest";
import { MAX_WATCHES, type ApiError, type Watch, type WatchesResponse } from "@bluebench/shared";
import { call, mockServices, signIn } from "./account.ts";

afterEach(() => vi.restoreAllMocks());

const list = async (cookie: string) => ((await (await call("GET", "/api/watches", { cookie })).json()) as WatchesResponse).watches;
const add = (cookie: string, vendor: string, product: string | null) => call("POST", "/api/watches", { cookie, body: { vendor, product } });

describe("watchlist", () => {
  it("needs an account", async () => {
    mockServices();
    expect((await call("GET", "/api/watches")).status).toBe(401);
    expect((await add("", "Fortinet", null)).status).toBe(401);
  });

  it("adds, lists and removes watches, without duplicates", async () => {
    const svc = mockServices();
    const { cookie } = await signIn(svc.mails);
    expect((await add(cookie, "Microsoft", "Exchange Server")).status).toBe(200);
    expect((await add(cookie, "microsoft", "exchange server")).status).toBe(200); // same watch, different case
    expect((await add(cookie, "Fortinet", "FortiOS")).status).toBe(200);
    expect((await list(cookie)).map((w) => [w.vendor, w.product])).toEqual([
      ["Fortinet", "FortiOS"],
      ["Microsoft", "Exchange Server"],
    ]);

    const fortiOs = (await list(cookie)).find((w) => w.vendor === "Fortinet")!;
    expect((await call("DELETE", `/api/watches/${fortiOs.id}`, { cookie })).status).toBe(200);
    expect((await list(cookie)).map((w) => w.vendor)).toEqual(["Microsoft"]);
  });

  it("watching a whole vendor replaces its single-product watches, and covers new ones", async () => {
    const svc = mockServices();
    const { cookie } = await signIn(svc.mails);
    await add(cookie, "Ivanti", "Connect Secure");
    await add(cookie, "Ivanti", "Policy Secure");
    const all = (await (await add(cookie, "Ivanti", null)).json()) as { watch: Watch };
    expect(all.watch.product).toBeNull();
    expect((await list(cookie)).map((w) => w.product)).toEqual([null]);
    // Already covered by the vendor watch: nothing new is stored.
    await add(cookie, "Ivanti", "EPMM");
    expect(await list(cookie)).toHaveLength(1);
  });

  it("caps the list and validates input", async () => {
    const svc = mockServices();
    const { cookie } = await signIn(svc.mails);
    for (let i = 0; i < MAX_WATCHES; i++) expect((await add(cookie, `Vendor ${i}`, null)).status).toBe(200);
    const over = await add(cookie, "One too many", null);
    expect(over.status).toBe(409);
    expect(((await over.json()) as ApiError).message).toContain(`${MAX_WATCHES}`);
    expect((await call("POST", "/api/watches", { cookie, body: { vendor: "" , product: null } })).status).toBe(400);
  });

  it("keeps each account's watches to itself", async () => {
    const svc = mockServices();
    const alice = await signIn(svc.mails);
    const bob = await signIn(svc.mails);
    await add(alice.cookie, "Apple", null);
    const [w] = await list(alice.cookie);
    expect((await call("DELETE", `/api/watches/${w!.id}`, { cookie: bob.cookie })).status).toBe(200); // no-op for Bob
    expect(await list(alice.cookie)).toHaveLength(1);
    expect(await list(bob.cookie)).toEqual([]);
  });
});
