import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/** In-memory localStorage for the node test environment. */
function fakeStorage() {
  const m = new Map<string, string>();
  return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), removeItem: (k: string) => void m.delete(k) };
}

const SIGNED_IN = { ok: true, signedIn: true, accountsEnabled: true, email: "a@example.org", emailAlerts: true, pushKey: null };

beforeEach(() => {
  vi.resetModules();
  vi.stubGlobal("localStorage", fakeStorage());
});
afterEach(() => vi.unstubAllGlobals());

describe("account store", () => {
  it("doesn't call the server for visitors who never signed in", async () => {
    const f = vi.fn();
    vi.stubGlobal("fetch", f);
    const { account } = await import("./account");
    await account.load();
    expect(f).not.toHaveBeenCalled();
    expect(account.get()).toMatchObject({ signedIn: false });
  });

  it("asks /api/me once when the hint says signed in", async () => {
    localStorage.setItem("bb.signedIn", "1");
    const f = vi.fn(async () => Response.json(SIGNED_IN));
    vi.stubGlobal("fetch", f);
    const { account } = await import("./account");
    await Promise.all([account.load(), account.load()]);
    expect(f).toHaveBeenCalledTimes(1);
    expect(f.mock.calls[0]).toMatchObject(["/api/me", { method: "GET" }]);
    expect(account.get()).toEqual(SIGNED_IN);
  });

  it("sets the hint on sign-in and clears it when the server says signed out", async () => {
    const f = vi
      .fn()
      .mockResolvedValueOnce(Response.json(SIGNED_IN))
      .mockResolvedValueOnce(Response.json({ ok: false, error: "signed-out", message: "You're signed out." }, { status: 401 }));
    vi.stubGlobal("fetch", f);
    const { account, finishSignIn, listDomains } = await import("./account");
    expect(await finishSignIn("t".repeat(32))).toEqual(SIGNED_IN);
    expect(localStorage.getItem("bb.signedIn")).toBe("1");
    expect(await listDomains()).toMatchObject({ ok: false, error: "signed-out" });
    expect(account.get()).toMatchObject({ signedIn: false });
    expect(localStorage.getItem("bb.signedIn")).toBeNull();
  });
});
