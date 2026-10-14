import { env, exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { sha256Hex, type ApiError, type CheckId, type DomainReport } from "@bluebench/shared";
import { REPORT_BUDGET, runReport } from "../src/domain/report.ts";
import { goodDomain, mockNet, type FakeNet } from "./net.ts";

let n = 0;
const uniq = (base = "example") => `${base}${n++}-${Date.now()}.test`;
/**
 * Report tests use a quota stub that always grants: the real crt.sh quota (5/min) would otherwise make
 * these tests depend on their order. Quota behaviour itself is covered in quota.test.ts.
 */
const openQuota = {
  idFromName: () => ({}),
  get: () => ({ acquire: async () => ({ ok: true }) }),
} as unknown as typeof env.PROVIDER_QUOTA;
const deps = { env: { ...env, PROVIDER_QUOTA: openQuota }, tier: "anon" as const, waitUntil: () => {} };
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
    expect(c.headers).toMatchObject({ status: "fail", summary: "Only 1 of 5 recommended security headers are set to protective values." });
    expect(c.cert.status).toBe("skipped"); // crt.sh down: not graded
  });

  it("recommends lock-down records for a domain that sends no email", async () => {
    const d = uniq();
    mockNet({ dns: { [d]: { A: ["93.184.215.14"] } }, crtsh: [] });
    const c = byId(await runReport(d, deps));
    expect(c.mx.status).toBe("info");
    // No MX says nothing about sending (#31): without SPF saying "no mail", a missing DKIM key still warns.
    expect(c.dkim.status).toBe("warn");
    expect(c.spf.fix).toContain("v=spf1 -all");
    expect(c.dmarc.fix).toContain("p=reject");
  });

  it("treats DKIM as not applicable only when SPF says the domain sends no mail (#31)", async () => {
    const d = uniq();
    mockNet({ dns: { [d]: { A: ["93.184.215.14"], TXT: ["v=spf1 -all"] } }, crtsh: [] });
    expect(byId(await runReport(d, deps)).dkim).toMatchObject({ status: "info", summary: expect.stringContaining("v=spf1 -all") });
  });

  describe("records the reviewer showed passing wrongly", () => {
    const mailDomain = (records: { txt?: string[]; dmarc?: string; dkim?: string }) => {
      const d = uniq();
      const net = goodDomain(d);
      if (records.txt) net.dns![d]!.TXT = records.txt;
      if (records.dmarc) net.dns![`_dmarc.${d}`] = { TXT: [records.dmarc] };
      if (records.dkim) net.dns![`selector1._domainkey.${d}`] = { TXT: [records.dkim] };
      mockNet(net);
      return d;
    };

    it.each([
      ["v=DMARC1; p=none; p=reject"],
      ["v=DMARC1; p=reject; p=none"],
    ])("fails a DMARC record with duplicate tags in either order: %s (#33)", async (dmarc) => {
      const c = byId(await runReport(mailDomain({ dmarc }), deps));
      expect(c.dmarc).toMatchObject({ status: "fail", summary: expect.stringContaining("repeats the p= tag") });
    });

    it("treats t=y as testing mode, one level below the policy (#32)", async () => {
      const c = byId(await runReport(mailDomain({ dmarc: "v=DMARC1; p=reject; t=y" }), deps));
      expect(c.dmarc).toMatchObject({ status: "warn", summary: "Policy p=reject is in testing mode (t=y), so receivers apply p=quarantine instead." });
    });

    it("explains that pct was removed, rather than treating it as the current rollout control (#32)", async () => {
      const c = byId(await runReport(mailDomain({ dmarc: "v=DMARC1; p=reject; pct=0" }), deps));
      expect(c.dmarc).toMatchObject({ status: "warn", summary: expect.stringContaining("RFC 9989") });
    });

    it.each(["v=spf1 ip4:not-an-ip -all", "v=spf1 include: -all", "v=spf1 definitely-not-a-mechanism -all"])(
      "fails syntactically invalid SPF: %s (#34)",
      async (spf) => {
        const c = byId(await runReport(mailDomain({ txt: [spf] }), deps));
        expect(c.spf).toMatchObject({ status: "fail", summary: expect.stringContaining("permerror") });
      },
    );

    it("fails a DKIM key that isn't a key (#38)", async () => {
      const c = byId(await runReport(mailDomain({ dkim: `v=DKIM1; k=rsa; p=${"!".repeat(300)}` }), deps));
      expect(c.dkim).toMatchObject({ status: "fail", summary: expect.stringContaining("isn't valid base64") });
    });
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

  it("retries crt.sh once with an exact-match query when it's overloaded", async () => {
    const d = uniq();
    const net = goodDomain(d);
    const rows = net.crtsh as object[];
    let first = true;
    const calls = mockNet(net);
    const real = vi.mocked(fetch).getMockImplementation()!;
    vi.mocked(fetch).mockImplementation(async (input, init) => {
      const u = new Request(input, init).url;
      if (u.startsWith("https://crt.sh/") && first) {
        first = false;
        calls.push(u);
        return new Response("Bad Gateway", { status: 502 });
      }
      return real(input, init);
    });
    const c = byId(await runReport(d, deps));
    expect(c.cert.status).toBe("pass");
    const crt = calls.filter((u) => u.startsWith("https://crt.sh/"));
    expect(crt).toHaveLength(2);
    expect(crt[1]).toContain("match=%3D");
    expect(rows.length).toBeGreaterThan(0);
  });

  describe("Cert Spotter fallback", () => {
    const inDays = (n: number) => new Date(Date.now() + n * 86_400_000).toISOString().replace(/\.\d+Z$/, "Z");
    let id = 1000;
    const issuance = (names: string[], from: number, to: number, extra: object = {}) => ({
      id: String(id++),
      dns_names: names,
      issuer: { friendly_name: "Let's Encrypt", name: "C=US, O=Let's Encrypt, CN=YE2" },
      not_before: inDays(from),
      not_after: inDays(to),
      revoked: false,
      ...extra,
    });

    it("is used when crt.sh is down, with our key, and the result names its source", async () => {
      const d = uniq();
      const calls = mockNet({ ...goodDomain(d), crtsh: 502, certspotter: [[issuance([d, `www.${d}`], -10, 80)]] });
      const auth: (string | null)[] = [];
      const real = vi.mocked(fetch).getMockImplementation()!;
      vi.mocked(fetch).mockImplementation(async (input, init) => {
        const req = new Request(input, init);
        if (req.url.startsWith("https://api.certspotter.com/")) auth.push(req.headers.get("authorization"));
        return real(input, init);
      });
      const r = await runReport(d, deps);
      const c = byId(r);
      expect(c.cert.status).toBe("pass");
      expect(c.cert.facts).toContainEqual({ label: "Source", value: "Cert Spotter" });
      expect(r.certificate?.issuer).toBe("Let's Encrypt");
      expect(auth).toEqual(["Bearer test-certspotter-key", "Bearer test-certspotter-key"]); // one page, then the empty page
      expect(calls.find((u) => u.startsWith("https://api.certspotter.com/"))).toContain("match_wildcards=true");
      expect(outbound(calls)).toBeLessThanOrEqual(REPORT_BUDGET);
    });

    it("is used when crt.sh answers with nothing", async () => {
      const d = uniq();
      mockNet({ ...goodDomain(d), crtsh: [], certspotter: [[issuance([`*.${d.slice(d.indexOf(".") + 1)}`, d], -10, 80)]] });
      expect(byId(await runReport(d, deps)).cert).toMatchObject({ status: "pass" });
    });

    it("reads every page, so it judges the newest certificate, and ignores revoked or unrelated ones", async () => {
      const d = uniq();
      const old = Array.from({ length: 100 }, () => issuance([d], -80, 10)); // would warn if judged alone
      mockNet({
        ...goodDomain(d),
        crtsh: 502,
        certspotter: [old, [issuance([d], -2, 88, { revoked: true }), issuance(["other.test"], -1, 89), issuance([d], -5, 85)]],
      });
      const c = byId(await runReport(d, deps)).cert;
      expect(c.status).toBe("pass");
      expect(c.facts).toContainEqual({ label: "Issued", value: inDays(-5).slice(0, 10) });
    });

    it("skips a domain with too many pages instead of judging a partial list", async () => {
      const d = uniq();
      const pages = Array.from({ length: 4 }, () => Array.from({ length: 100 }, () => issuance([d], -80, 10)));
      mockNet({ ...goodDomain(d), crtsh: 502, certspotter: pages });
      expect(byId(await runReport(d, deps)).cert).toMatchObject({
        status: "skipped",
        summary: "Couldn't check certificates this time: crt.sh is overloaded right now, and the domain has too many certificates to check quickly.",
      });
    });

    it("leaves the check skipped (with crt.sh's reason) when the fallback fails too", async () => {
      const d = uniq();
      mockNet({ ...goodDomain(d), crtsh: 502, certspotter: 429 });
      expect(byId(await runReport(d, deps)).cert).toMatchObject({ status: "skipped", summary: "Couldn't check certificates this time: crt.sh is overloaded right now, and Cert Spotter didn't answer." });
    });

    it("isn't asked when crt.sh has the answer", async () => {
      const d = uniq();
      const calls = mockNet({ ...goodDomain(d), certspotter: [[issuance([d], -1, 89)]] });
      expect(byId(await runReport(d, deps)).cert.facts).toContainEqual({ label: "Source", value: "crt.sh" });
      expect(calls.some((u) => u.startsWith("https://api.certspotter.com/"))).toBe(false);
    });
  });

  it("doesn't grade or cache an empty crt.sh answer", async () => {
    const d = uniq();
    mockNet({ ...goodDomain(d), crtsh: [] });
    expect(byId(await runReport(d, deps)).cert.status).toBe("skipped");
    expect(await env.VERDICTS.get(`cert:v2:${await sha256Hex(d)}`)).toBeNull();
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

  it("counts a site with a long redirect chain as working, without following past 3 redirects", async () => {
    const d = uniq();
    const net = goodDomain(d);
    const hsts = { "strict-transport-security": "max-age=31536000" };
    net.sites = {
      [`https://${d}/`]: { status: 302, headers: { location: `https://${d}/a`, ...hsts } },
      [`https://${d}/a`]: { status: 302, headers: { location: `https://${d}/b` } },
      [`https://${d}/b`]: { status: 302, headers: { location: `https://${d}/c` } },
      [`https://${d}/c`]: { status: 302, headers: { location: `https://${d}/d` } },
      [`https://${d}/d`]: { status: 200 },
      [`http://${d}/`]: { status: 301, headers: { location: `https://${d}/` } },
    };
    const calls = mockNet(net);
    const c = byId(await runReport(d, deps));
    expect(c.https.status).toBe("pass");
    expect(c.https.facts).toContainEqual({ label: "HTTPS response", value: "stopped after 4 redirects" });
    expect(c.hsts.status).toBe("pass"); // from the first response
    expect(c.headers.status).toBe("skipped");
    expect(calls).not.toContain(`https://${d}/d`); // the 4th redirect is never followed
  });

  it("follows plain-HTTP redirects to see if they end up on HTTPS, without fetching the HTTPS URL", async () => {
    const d = uniq();
    const net = goodDomain(d);
    net.sites![`http://${d}/`] = { status: 301, headers: { location: "/mail/" } };
    net.sites![`http://${d}/mail/`] = { status: 302, headers: { location: `https://${d}/mail/` } };
    const calls = mockNet(net);
    const c = byId(await runReport(d, deps));
    expect(c.https).toMatchObject({ status: "pass" });
    expect(c.https.facts).toContainEqual({ label: "Plain HTTP", value: `301 → /mail/, 302 → https://${d}/mail/` });
    expect(calls).not.toContain(`https://${d}/mail/`);
  });

  it("warns rather than fails on missing SPF for a domain without mail servers", async () => {
    const d = uniq();
    mockNet({ dns: { [d]: { A: ["93.184.215.14"] } }, crtsh: [] });
    expect(byId(await runReport(d, deps)).spf).toMatchObject({ status: "warn", fix: expect.stringContaining("v=spf1 -all") });
  });

  it("doesn't fetch sites in its own Cloudflare zone, and doesn't grade those checks", async () => {
    const net = goodDomain("bluebench.dev");
    net.sites = {}; // any fetch of the site would fail the HTTPS check
    const calls = mockNet(net);
    const r = await runReport("bluebench.dev", { ...deps, selfZone: "bluebench.dev" });
    const c = byId(r);
    for (const id of ["https", "hsts", "headers"] as const) {
      expect(c[id]).toMatchObject({ status: "skipped", summary: expect.stringContaining("own Cloudflare zone") });
    }
    expect(calls.some((u) => /^https?:\/\/bluebench\.dev\//.test(u))).toBe(false);
    expect(r.grade).toBe("A"); // email, DNS and certificate checks still count
    // Other domains are unaffected.
    expect(byId(await runReport(uniq(), { ...deps, selfZone: "bluebench.dev" })).https.status).not.toBe("skipped");
  });

  it("fails HTTPS on a server error page and doesn't grade the error page's headers", async () => {
    const d = uniq();
    const net = goodDomain(d);
    net.sites![`https://${d}/`] = { status: 522, headers: { "x-frame-options": "SAMEORIGIN", "referrer-policy": "same-origin" } };
    mockNet(net);
    const c = byId(await runReport(d, deps));
    expect(c.https).toMatchObject({ status: "fail", summary: expect.stringContaining("server error (522)") });
    expect(c.https.facts).toContainEqual({ label: "HTTPS response", value: `522 from https://${d}/` });
    expect(c.hsts.status).toBe("skipped");
    expect(c.headers.status).toBe("skipped");
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

    const key = `report:v2:${await sha256Hex(d)}`;
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

  it("treats the zone it's served from as its own (web checks not run)", async () => {
    mockNet(goodDomain("bluebench.dev"));
    const check = await session();
    const r = (await (await check("bluebench.dev")).json()) as DomainReport;
    expect(r.checks.find((c) => c.id === "headers")!.summary).toContain("own Cloudflare zone");
  });

  it("limits fresh checks of one target domain to 5 a minute", async () => {
    const d = uniq("target");
    mockNet(goodDomain(d));
    const key = `report:v2:${await sha256Hex(d)}`;
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) {
      const check = await session(); // different sessions and IPs: the limit is per target
      const status = (await check(d)).status;
      statuses.push(status);
      if (status === 200) {
        // The cache write happens after the response (waitUntil). Wait for it, then remove it so the
        // next request is a fresh run that has to pass the per-target limit.
        await vi.waitFor(async () => {
          if (!(await env.VERDICTS.get(key))) throw new Error("not cached yet");
        });
        await env.VERDICTS.delete(key);
      }
    }
    expect(statuses.slice(0, 5)).toEqual([200, 200, 200, 200, 200]);
    expect(statuses[5]).toBe(429);
  });
});
