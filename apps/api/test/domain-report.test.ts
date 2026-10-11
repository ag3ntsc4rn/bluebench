import { env, exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { sha256Hex, type ApiError, type CheckId, type DomainReport } from "@bluebench/shared";
import { REPORT_BUDGET, runReport } from "../src/domain/report.ts";
import { goodDomain, mockNet, type FakeNet } from "./net.ts";

let n = 0;
const uniq = (base = "example") => `${base}${n++}-${Date.now()}.test`;
const deps = { env, tier: "anon" as const, waitUntil: () => {} };
const byId = (r: DomainReport) => Object.fromEntries(r.checks.map((c) => [c.id, c])) as Record<CheckId, DomainReport["checks"][number]>;
const outbound = (calls: string[]) => calls.filter((u) => !u.includes("challenges.cloudflare.com")).length;

afterEach(() => vi.restoreAllMocks());

describe("runReport", () => {
  it("gives a well-run domain an A, within the subrequest budget", async () => {
    const d = uniq();
    const calls = mockNet(goodDomain(d));
    const r = await runReport(d, deps);
    const c = byId(r);
    expect(r.grade).toBe("A");
    expect(r.score).toBe(100);
    for (const id of ["spf", "dmarc", "dkim", "dnssec", "https", "hsts", "headers", "cert"] as const) {
      expect(c[id].status, `${id}: ${c[id].summary}`).toBe("pass");
    }
    expect(c.mx).toMatchObject({ status: "pass", facts: [{ label: "Primary", value: `mx1.${d}` }, { label: "Backup", value: `mx2.${d}` }] });
    expect(c.spf.facts).toContainEqual({ label: "DNS lookups", value: "1 of 10" });
    expect(c.dkim.summary).toContain("1 DKIM key");
    expect(c.cert.summary).toMatch(/in (79|80) days, issued by Let's Encrypt/);
    expect(outbound(calls)).toBeLessThanOrEqual(REPORT_BUDGET);
  });

  it("fails a neglected domain and says how to fix each problem", async () => {
    const d = uniq();
    mockNet({
      dns: { [d]: { A: ["93.184.215.14"], MX: [`10 mx.${d}.`] } },
      sites: {
        [`https://${d}/`]: { headers: { "x-content-type-options": "nosniff" } },
        [`http://${d}/`]: { status: 200 },
      },
      crtsh: 502,
    });
    const r = await runReport(d, deps);
    const c = byId(r);
    expect(r.grade).toBe("F");
    expect(c.spf).toMatchObject({ status: "fail", fix: expect.stringContaining(`TXT record at ${d}`) });
    expect(c.dmarc).toMatchObject({ status: "fail", fix: expect.stringContaining(`_dmarc.${d}: v=DMARC1; p=none`) });
    expect(c.dkim.status).toBe("warn");
    expect(c.dnssec.status).toBe("warn");
    expect(c.https).toMatchObject({ status: "warn", summary: expect.stringContaining("doesn't redirect") });
    expect(c.hsts.status).toBe("fail");
    expect(c.headers).toMatchObject({ status: "fail", summary: "Only 1 of 5 recommended security headers are set." });
    expect(c.cert.status).toBe("skipped"); // crt.sh down: not graded
  });

  it("recommends lock-down records for a domain that sends no email", async () => {
    const d = uniq();
    mockNet({ dns: { [d]: { A: ["93.184.215.14"] } }, crtsh: [] });
    const c = byId(await runReport(d, deps));
    expect(c.mx.status).toBe("info");
    expect(c.dkim.status).toBe("info");
    expect(c.spf.fix).toContain("v=spf1 -all");
    expect(c.dmarc.fix).toContain("p=reject");
  });

  it("fails SPF that needs more than 10 DNS lookups", async () => {
    const d = uniq();
    const net: FakeNet = { dns: { [d]: { TXT: [`v=spf1 include:i0.${d} -all`] } }, crtsh: [] };
    for (let i = 0; i < 11; i++) net.dns![`i${i}.${d}`] = { TXT: [`v=spf1 include:i${i + 1}.${d} ip4:192.0.2.${i}`] };
    mockNet(net);
    const c = byId(await runReport(d, deps));
    expect(c.spf).toMatchObject({ status: "fail", summary: expect.stringContaining("more than 10 DNS lookups") });
  });

  it("fails multiple SPF records", async () => {
    const d = uniq();
    mockNet({ dns: { [d]: { TXT: ["v=spf1 -all", "v=spf1 include:x.test ~all"] } }, crtsh: [] });
    expect(byId(await runReport(d, deps)).spf.status).toBe("fail");
  });

  it("applies the parent domain's DMARC policy (sp=) to a subdomain", async () => {
    mockNet({
      dns: {
        "mail.parent.test": { MX: ["10 mx.parent.test."] },
        "_dmarc.parent.test": { TXT: ["v=DMARC1; p=reject; sp=none"] },
      },
      crtsh: [],
    });
    const c = byId(await runReport("mail.parent.test", deps));
    expect(c.dmarc.status).toBe("warn"); // sp=none governs subdomains
    expect(c.dmarc.facts).toContainEqual({ label: "Inherited from", value: "parent.test" });
  });

  it("flags broken DNSSEC", async () => {
    const d = uniq();
    mockNet({ dns: { [d]: { servfail: true } }, crtsh: [] });
    expect(byId(await runReport(d, deps)).dnssec.status).toBe("fail");
  });

  it("never connects to a domain that resolves to a private address", async () => {
    const d = uniq();
    const calls = mockNet({ dns: { [d]: { A: ["10.0.0.5"] } }, sites: { [`https://${d}/`]: {} }, crtsh: [] });
    const c = byId(await runReport(d, deps));
    expect(c.https).toMatchObject({ status: "fail", summary: expect.stringContaining("non-public") });
    expect(calls.some((u) => u.startsWith(`https://${d}`) || u.startsWith(`http://${d}`))).toBe(false);
  });

  it("treats a domain with no address as having no website (not a failure)", async () => {
    const d = uniq();
    mockNet({ dns: { [d]: { MX: [`10 mx.${d}.`] } }, crtsh: [] });
    const c = byId(await runReport(d, deps));
    for (const id of ["https", "hsts", "headers"] as const) expect(c[id].status).toBe("info");
  });

  it("stays within budget when SPF includes fan out, skipping instead of failing", async () => {
    const d = uniq();
    const includes = Array.from({ length: 9 }, (_, i) => `include:f${i}.${d}`).join(" ");
    const net = goodDomain(d);
    net.dns![d]!.TXT = [`v=spf1 ${includes} -all`];
    for (let i = 0; i < 9; i++) net.dns![`f${i}.${d}`] = { TXT: [`v=spf1 a mx ip4:192.0.2.${i}`] };
    const calls = mockNet(net);
    const r = await runReport(d, deps);
    expect(outbound(calls)).toBeLessThanOrEqual(REPORT_BUDGET);
    expect(r.checks).toHaveLength(9);
  });
});

describe("POST /api/domain", () => {
  let ip = 1;
  async function session() {
    const addr = `198.51.100.${200 + (ip++ % 50)}`;
    const res = await exports.default.fetch("https://bluebench.dev/api/session", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": addr },
      body: JSON.stringify({ turnstileToken: "ok" }),
    });
    const cookie = res.headers.get("set-cookie")!.split(";")[0]!;
    return (domain: string) =>
      exports.default.fetch("https://bluebench.dev/api/domain", {
        method: "POST",
        headers: { "content-type": "application/json", cookie, "cf-connecting-ip": addr },
        body: JSON.stringify({ domain }),
      });
  }

  it("needs a session", async () => {
    const res = await exports.default.fetch("https://bluebench.dev/api/domain", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain: "example.com" }),
    });
    expect(res.status).toBe(401);
  });

  it.each(["", "localhost", "10.0.0.1", "not a domain", "https://example.com/"])("rejects %j", async (domain) => {
    mockNet({});
    const check = await session();
    const res = await check(domain);
    expect(res.status).toBe(400);
    expect(((await res.json()) as ApiError).message).toBe("Enter a domain name, like example.com.");
  });

  it("returns a graded report, then serves it from a cache that doesn't contain the domain", async () => {
    const d = uniq("cached");
    mockNet(goodDomain(d));
    const check = await session();
    const first = (await (await check(d.toUpperCase())).json()) as DomainReport;
    expect(first).toMatchObject({ ok: true, domain: d, grade: "A" });
    expect(first.cached).toBeUndefined();

    const key = `report:v1:${await sha256Hex(d)}`;
    const raw = await vi.waitFor(async () => {
      const v = await env.VERDICTS.get(key);
      if (!v) throw new Error("not cached yet");
      return v;
    });
    expect(raw).not.toContain(d);

    const again = (await (await check(d)).json()) as DomainReport;
    expect(again).toMatchObject({ cached: true, domain: d, grade: "A" });
    expect(again.checks.find((c) => c.id === "mx")!.facts[0]!.value).toBe(`mx1.${d}`); // placeholder restored
  });

  it("limits fresh checks of one target domain to 5 a minute", async () => {
    const d = uniq("target");
    mockNet(goodDomain(d));
    const key = `report:v1:${await sha256Hex(d)}`;
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) {
      const check = await session(); // different sessions and IPs: the limit is per target
      await env.VERDICTS.delete(key); // force a fresh run each time
      statuses.push((await check(d)).status);
    }
    expect(statuses.slice(0, 5)).toEqual([200, 200, 200, 200, 200]);
    expect(statuses[5]).toBe(429);
  });
});
