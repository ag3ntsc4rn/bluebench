import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { lookalikes } from "@bluebench/shared";
import { eq } from "drizzle-orm";
import { db } from "../src/auth.ts";
import { alert, domain, lookalike, user } from "../src/db/schema.ts";
import { Budget, Resolver } from "../src/dns.ts";
import { LOOKALIKE_BUDGET, probe, scanLookalikes } from "../src/monitor/lookalike.ts";
import { watchLookalikes } from "../src/monitor/run.ts";
import { freshEmail } from "./account.ts";
import { mockNet, type Zone } from "./net.ts";

afterEach(() => vi.restoreAllMocks());

const DAY = 86_400_000;
const NOW = Date.now();
const d = () => db(env);
let n = 0;
/** Short names keep the variant list small enough to reason about, but over one run's budget. */
const uniq = () => `brand${n++}x${NOW % 100000}.com`;

async function seed(name: string, extra: string[] = []) {
  const userId = crypto.randomUUID();
  const t = new Date(NOW - 30 * DAY);
  await d().insert(user).values({ id: userId, name: "", email: freshEmail(), emailVerified: true, createdAt: t, updatedAt: t });
  const ids: string[] = [];
  for (const nm of [name, ...extra]) {
    const id = crypto.randomUUID();
    ids.push(id);
    await d().insert(domain).values({ id, userId, name: nm, verifyToken: "0123456789abcdef0123456789abcdef", verifiedAt: t, createdAt: t });
  }
  return { id: ids[0]!, userId };
}
const row = async (id: string) => (await d().select().from(domain).where(eq(domain.id, id)))[0]!;
const hits = async (id: string) => (await d().select().from(lookalike).where(eq(lookalike.domainId, id))).map((h) => h.name).sort();

/** Scan until the pass finishes (the list is longer than one run's budget). */
async function fullScan(id: string, now = NOW, exclude = new Set<string>()) {
  const fresh: string[] = [];
  for (let i = 0; i < 20; i++) {
    const r = await scanLookalikes(d(), await row(id), now, exclude);
    fresh.push(...r.fresh.map((f) => f.name));
    if (r.finished) return { fresh, runs: i + 1 };
  }
  throw new Error("scan never finished");
}

describe("probe", () => {
  const r = (dns: Record<string, Zone>) => {
    mockNet({ dns });
    return new Resolver(new Budget(10));
  };

  it("costs one query for a name nobody registered", async () => {
    const calls = mockNet({ dns: {} });
    expect(await probe(new Resolver(new Budget(10)), "nobody.example")).toEqual({ exists: false });
    expect(calls).toHaveLength(1);
  });

  it("reports a website and mail", async () => {
    expect(await probe(r({ "x.example": { A: ["192.0.2.1"], MX: ["10 mx.x.example."] } }), "x.example")).toEqual({ exists: true, web: true, mail: true });
  });

  it("doesn't count a null MX as mail", async () => {
    expect(await probe(r({ "x.example": { MX: ["0 ."] } }), "x.example")).toEqual({ exists: true, web: false, mail: false });
  });

  it("throws on SERVFAIL instead of calling the name gone", async () => {
    await expect(probe(r({ "x.example": { servfail: true } }), "x.example")).rejects.toThrow();
  });
});

describe("scanLookalikes", () => {
  it("records a baseline without alerting, spread across runs within budget", async () => {
    const name = uniq();
    const [v1, v2] = lookalikes(name).map((l) => l.domain);
    const calls = mockNet({ dns: { [v1!]: { A: ["192.0.2.1"] }, [v2!]: { MX: ["10 mx.elsewhere.example."] } } });
    const { id } = await seed(name);

    const first = await scanLookalikes(d(), await row(id), NOW, new Set());
    expect(first.finished).toBe(false);
    expect(calls.length).toBeLessThanOrEqual(LOOKALIKE_BUDGET);
    expect((await row(id)).lookalikeCursor).toBeGreaterThan(0);

    const { fresh } = await fullScan(id);
    expect(fresh).toEqual([]);
    expect(await hits(id)).toEqual([v1, v2].sort());
    const after = await row(id);
    expect(after.lookalikeCursor).toBe(0);
    expect(after.lookalikeScannedAt?.getTime()).toBe(NOW);
  });

  it("reports new lookalikes after the baseline, and forgets ones that stop resolving", async () => {
    const name = uniq();
    const [v1, v2] = lookalikes(name).map((l) => l.domain);
    mockNet({ dns: { [v1!]: { A: ["192.0.2.1"] } } });
    const { id } = await seed(name);
    await fullScan(id);

    vi.restoreAllMocks();
    mockNet({ dns: { [v2!]: { A: ["192.0.2.2"], MX: ["10 mx.example."] } } });
    const { fresh } = await fullScan(id, NOW + DAY);
    expect(fresh).toEqual([v2]);
    expect(await hits(id)).toEqual([v2]);
  });

  it("keeps a known lookalike when DNS fails for it", async () => {
    const name = uniq();
    const [v1] = lookalikes(name).map((l) => l.domain);
    mockNet({ dns: { [v1!]: { A: ["192.0.2.1"] } } });
    const { id } = await seed(name);
    await fullScan(id);

    vi.restoreAllMocks();
    mockNet({ dns: { [v1!]: { servfail: true } } });
    await fullScan(id, NOW + DAY);
    expect(await hits(id)).toEqual([v1]);
  });
});

describe("watchLookalikes", () => {
  it("sends one defanged alert per run, and skips the owner's other domains", async () => {
    const name = uniq();
    const [v1, v2, v3] = lookalikes(name).map((l) => l.domain);
    mockNet({ dns: {} });
    const { id, userId } = await seed(name, [v3!]);
    await fullScan(id);

    vi.restoreAllMocks();
    mockNet({ dns: { [v1!]: { A: ["192.0.2.1"] }, [v2!]: { MX: ["10 mx.example."] }, [v3!]: { A: ["192.0.2.3"] } } });
    await d().update(domain).set({ lookalikeScannedAt: new Date(NOW - DAY) }).where(eq(domain.id, id));
    for (let i = 0; i < 20 && (await row(id)).lookalikeScannedAt!.getTime() !== NOW + DAY; i++) {
      await watchLookalikes(d(), await row(id), NOW + DAY);
    }

    const alerts = await d().select().from(alert).where(eq(alert.userId, userId));
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({ kind: "lookalike", domain: name, title: `${name}: 2 new lookalike domains` });
    expect(alerts[0]!.body).toContain(`${v1!.replace(/\./g, "[.]")} (website)`);
    expect(alerts[0]!.body).toContain(`${v2!.replace(/\./g, "[.]")} (mail)`);
    expect(alerts[0]!.body).not.toContain(v3!.replace(/\./g, "[.]"));
    expect(await hits(id)).toEqual([v1, v2].sort());
  });
});
