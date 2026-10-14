import { env, exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MAX_SAVED_DOMAINS, MAX_WATCHES } from "@bluebench/shared";
import { eq } from "drizzle-orm";
import { db } from "../src/auth.ts";
import { alert, domain, intelState, session, user, watch } from "../src/db/schema.ts";
import { Budget } from "../src/dns.ts";
import { certCheck } from "../src/domain/cert.ts";
import { MAX_BODY_BYTES } from "../src/http.ts";
import { tick } from "../src/monitor/run.ts";
import { call, freshEmail, mockServices, signIn } from "./account.ts";

afterEach(() => vi.restoreAllMocks());
const d = () => db(env);

describe("request bodies (#40)", () => {
  it("refuses a declared-oversized body before reading it", async () => {
    const res = await exports.default.fetch("https://bluebench.dev/api/session", {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": String(MAX_BODY_BYTES + 1), origin: "https://bluebench.dev" },
      body: "{}",
    });
    expect(res.status).toBe(413);
  });

  it("stops reading an oversized body sent without a length", async () => {
    let pulled = 0;
    const chunk = new Uint8Array(64 * 1024).fill(0x20);
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled++;
        if (pulled > 200) controller.close(); // ~12.5 MB if read to the end
        else controller.enqueue(chunk);
      },
    });
    const res = await exports.default.fetch(
      new Request("https://bluebench.dev/api/session", { method: "POST", headers: { "content-type": "application/json", origin: "https://bluebench.dev" }, body: stream, duplex: "half" } as RequestInit),
    );
    expect(res.status).toBe(413);
    expect(pulled).toBeLessThan(20); // cancelled soon after passing the cap
  });
});

describe("crt.sh quota (#41)", () => {
  const permits = (grant: boolean[]) => {
    const asked: string[] = [];
    const quota = {
      idFromName: (n: string) => n,
      get: (n: string) => ({ acquire: async () => (asked.push(n), { ok: grant[asked.length - 1] ?? true, reason: "rate" }) }),
    } as unknown as typeof env.PROVIDER_QUOTA;
    return { asked, env: { ...env, PROVIDER_QUOTA: quota, CERTSPOTTER_API_KEY: undefined } };
  };
  const crtsh = (first: Response) => {
    const urls: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const u = new Request(input).url;
      urls.push(u);
      return urls.length === 1 ? first : Response.json([{ issuer_name: "O=Test", name_value: "q41.example", not_before: "2026-01-01T00:00:00", not_after: "2027-01-01T00:00:00" }]);
    });
    return urls;
  };
  const deps = (e: typeof env) => ({ env: e, budget: new Budget(10), tier: "user" as const, waitUntil: () => {}, now: Date.parse("2026-10-14T00:00:00Z") });

  it("takes a permit for the retry as well as the first request", async () => {
    const q = permits([true, true]);
    const urls = crtsh(new Response("busy", { status: 502 }));
    expect((await certCheck(`q41a-${Date.now()}.example`, deps(q.env))).status).not.toBe("error");
    expect(urls).toHaveLength(2);
    expect(q.asked).toEqual(["crtsh", "crtsh"]);
  });

  it("doesn't retry when the second permit is refused", async () => {
    const q = permits([true, false]);
    const urls = crtsh(new Response("busy", { status: 502 }));
    const c = await certCheck(`q41b-${Date.now()}.example`, deps(q.env));
    expect(urls).toHaveLength(1);
    expect(c).toMatchObject({ status: "skipped", summary: expect.stringContaining("crt.sh is overloaded") });
  });
});

describe("retention cleanup (#42)", () => {
  it("runs within the hour even when other work is always waiting, then stays out of the way", async () => {
    const now = Date.parse("2026-10-14T09:17:00Z");
    const t = new Date(now);
    await d().delete(intelState);
    const userId = crypto.randomUUID();
    await d().insert(user).values({ id: userId, name: "", email: freshEmail(), emailVerified: true, createdAt: t, updatedAt: t });
    await d().insert(session).values({ id: crypto.randomUUID(), token: crypto.randomUUID(), userId, expiresAt: new Date(now - 1000), createdAt: t, updatedAt: t });
    // Backlog: an undelivered alert that would otherwise win every run.
    await d().insert(alert).values({ id: crypto.randomUUID(), userId, kind: "test", title: "x", body: "x", createdAt: t });
    const old = crypto.randomUUID();
    await d().insert(alert).values({ id: old, userId, kind: "test", title: "old", body: "old", createdAt: new Date(now - 200 * 86_400_000), deliveredAt: t });

    mockServices();
    expect(await tick(env, { now, waitUntil: () => {} })).toBe("housekeeping");
    expect(await d().select().from(alert).where(eq(alert.id, old))).toEqual([]);
    expect(await d().select().from(session).where(eq(session.userId, userId))).toEqual([]);
    expect(await tick(env, { now: now + 60_000, waitUntil: () => {} })).not.toBe("housekeeping");
    expect(await tick(env, { now: now + 3_600_000, waitUntil: () => {} })).toBe("housekeeping");
  });
});

describe("collection caps under overlapping requests (#39)", () => {
  it("never stores more than the domain cap", async () => {
    const svc = mockServices();
    const { cookie, email } = await signIn(svc.mails);
    const sends = Array.from({ length: MAX_SAVED_DOMAINS + 4 }, (_, i) => call("POST", "/api/domains", { cookie, body: { domain: `race${i}-${Date.now()}.example` } }));
    const statuses = (await Promise.all(sends)).map((r) => r.status);
    expect(statuses.filter((s) => s === 200)).toHaveLength(MAX_SAVED_DOMAINS);
    const [me] = await d().select().from(user).where(eq(user.email, email));
    expect(await d().select().from(domain).where(eq(domain.userId, me!.id))).toHaveLength(MAX_SAVED_DOMAINS);
  });

  it("stores one row for identical overlapping watches, and never more than the watch cap", async () => {
    const svc = mockServices();
    const { cookie } = await signIn(svc.mails);
    const same = await Promise.all(Array.from({ length: 5 }, () => call("POST", "/api/watches", { cookie, body: { vendor: "Ivanti", product: "Connect Secure" } })));
    expect(same.every((r) => r.status === 200)).toBe(true);
    const list = async () => ((await (await call("GET", "/api/watches", { cookie })).json()) as { watches: unknown[] }).watches;
    expect(await list()).toHaveLength(1);

    await Promise.all(Array.from({ length: MAX_WATCHES + 5 }, (_, i) => call("POST", "/api/watches", { cookie, body: { vendor: `Vendor ${i}`, product: null } })));
    expect((await list()).length).toBeLessThanOrEqual(MAX_WATCHES);
  });

  it("migration keeps watches unique per user, vendor and product", async () => {
    const t = new Date();
    const userId = crypto.randomUUID();
    await d().insert(user).values({ id: userId, name: "", email: freshEmail(), emailVerified: true, createdAt: t, updatedAt: t });
    const row = { userId, vendor: "Apple", product: "iOS", vendorKey: "apple", productKey: "ios", createdAt: t };
    await d().insert(watch).values({ id: crypto.randomUUID(), ...row });
    await expect(d().insert(watch).values({ id: crypto.randomUUID(), ...row })).rejects.toThrow();
  });
});
