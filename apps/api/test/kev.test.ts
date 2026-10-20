import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it } from "vitest";
import { KEV_KV_KEYS, type KevEntry, type KevResponse } from "@bluebench/shared";
import { eq } from "drizzle-orm";
import { db } from "../src/auth.ts";
import { alert, intelState, kevSeen, user, watch } from "../src/db/schema.ts";
import { checkKev, KEV_SEEN_RETENTION_MS, kevAlert, pruneKevSeen } from "../src/monitor/kev.ts";
import { tick } from "../src/monitor/run.ts";
import { freshEmail } from "./account.ts";

const d = () => db(env);
const NOW = Date.parse("2026-10-13T14:30:00Z");
let n = 0;

const entry = (vendor: string, product: string, extra: Partial<KevEntry> = {}): KevEntry => ({
  cve: `CVE-2026-${50000 + n++}`,
  vendor,
  product,
  name: `${vendor} ${product} flaw`,
  added: "2026-10-12",
  description: "Remote code execution.",
  action: "Apply the vendor's update or mitigation.",
  due: "2026-11-02",
  ransomware: false,
  ...extra,
});

async function publish(entries: KevEntry[], updatedAt: string) {
  const doc: KevResponse = { ok: true, updatedAt, catalogVersion: "2026.10.13", epssDate: null, entries };
  await env.VERDICTS.put(KEV_KV_KEYS.recent, JSON.stringify(doc));
}

async function person(watches: { vendor: string; product: string | null }[]) {
  const id = crypto.randomUUID();
  const t = new Date(NOW);
  await d().insert(user).values({ id, name: "", email: freshEmail(), emailVerified: true, createdAt: t, updatedAt: t });
  for (const w of watches) {
    await d().insert(watch).values({ id: crypto.randomUUID(), userId: id, vendor: w.vendor, product: w.product, vendorKey: w.vendor.toLowerCase(), createdAt: t });
  }
  return id;
}
const alertsFor = (userId: string) => d().select().from(alert).where(eq(alert.userId, userId));

afterEach(async () => {
  await d().delete(intelState);
  await d().delete(kevSeen);
  await env.VERDICTS.delete(KEV_KV_KEYS.recent);
});

describe("checkKev", () => {
  it("does nothing until data exists, then records a silent baseline", async () => {
    const fan = await person([{ vendor: "Fortinet", product: null }]);
    expect(await checkKev(env, d(), NOW)).toBe("no-data");
    await publish([entry("Fortinet", "FortiOS")], "2026-10-13T14:15:00Z");
    expect(await checkKev(env, d(), NOW)).toBe("baseline");
    expect(await alertsFor(fan)).toEqual([]);
    expect(await checkKev(env, d(), NOW)).toBe("unchanged");
  });

  it("alerts each matching account once, for a vendor or a single product, and nobody else", async () => {
    const old = entry("Fortinet", "FortiOS");
    await publish([old], "v1");
    await checkKev(env, d(), NOW);

    const allFortinet = await person([{ vendor: "fortinet", product: null }]);
    const justExchange = await person([{ vendor: "Microsoft", product: "Exchange Server" }]);
    const bystander = await person([{ vendor: "Apple", product: null }]);

    const forti = entry("Fortinet", "FortiProxy", { ransomware: true });
    const exch = entry("Microsoft", "Exchange Server");
    const win = entry("Microsoft", "Windows");
    await publish([forti, exch, win, old], "v2");
    expect(await checkKev(env, d(), NOW)).toBe("checked");

    const [a] = await alertsFor(allFortinet);
    expect(a).toMatchObject({ kind: "kev", domain: null, title: `Fortinet FortiProxy: actively exploited (${forti.cve})` });
    expect(a!.body).toContain("Used in ransomware.");
    expect(a!.body).toContain("https://bluebench.dev/exploited-vulnerabilities");
    expect(a!.body).not.toContain(old.cve); // seen in the baseline

    const [b, ...more] = await alertsFor(justExchange);
    expect(more).toEqual([]);
    expect(b!.title).toContain(exch.cve);
    expect(b!.body).not.toContain(win.cve);

    expect(await alertsFor(bystander)).toEqual([]);

    // The same entries again (e.g. the list refreshed for new EPSS scores) don't alert twice.
    await publish([forti, exch, win, old], "v3");
    await checkKev(env, d(), NOW);
    expect(await alertsFor(allFortinet)).toHaveLength(1);
  });

  it("forgets seen entries only long after they've left the 90-day list", async () => {
    await d().insert(kevSeen).values([
      { cve: "CVE-2000-0001", seenAt: new Date(NOW - KEV_SEEN_RETENTION_MS - 1000) },
      { cve: "CVE-2026-0001", seenAt: new Date(NOW - 100 * 86_400_000) },
    ]);
    await pruneKevSeen(d(), NOW);
    expect((await d().select().from(kevSeen)).map((r) => r.cve)).toEqual(["CVE-2026-0001"]);
  });
});

describe("kevAlert", () => {
  it("summarises several entries in one alert", () => {
    const text = kevAlert([entry("Ivanti", "Connect Secure"), entry("Ivanti", "Policy Secure")], "https://bluebench.dev");
    expect(text.title).toBe("2 newly exploited vulnerabilities in products you watch");
    expect(text.body.split("\n").filter((l) => l.startsWith("CVE-"))).toHaveLength(2);
  });
});

describe("tick", () => {
  it("runs the watchlist check at minute 30", async () => {
    await publish([entry("Fortinet", "FortiOS")], "v1");
    await d().insert(intelState).values({ key: "housekeeping_at", value: String(NOW) }); // cleanup isn't due
    // Earlier tests leave alerts pending; delivering them would take this run (and call the real
    // email and push services, which made this test time out now and then).
    await d().update(alert).set({ deliveredAt: new Date(NOW) });
    expect(await tick(env, { now: NOW, waitUntil: () => {} })).toBe("intel");
  });
});
