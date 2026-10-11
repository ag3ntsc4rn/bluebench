import { afterEach, describe, expect, it, vi } from "vitest";
import { assertSafeUrl, BlockedUrlError, safeFetch } from "../src/safe-fetch.ts";

/** Fake DNS-over-HTTPS + origin server. `dns` maps host → addresses; `pages` maps URL → response. */
function mockNet(dns: Record<string, string[]>, pages: Record<string, () => Response> = {}) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.hostname === "cloudflare-dns.com") {
      const name = url.searchParams.get("name")!;
      const type = url.searchParams.get("type");
      const answers = (dns[name] ?? [])
        .filter((a) => (type === "AAAA") === a.includes(":"))
        .map((data) => ({ type: type === "AAAA" ? 28 : 1, data }));
      return Response.json({ Status: dns[name] ? 0 : 3, Answer: answers });
    }
    const page = pages[url.href];
    if (!page) throw new Error(`unexpected fetch ${url.href}`);
    return page();
  });
}

const redirect = (to: string) => () => new Response(null, { status: 302, headers: { location: to } });

afterEach(() => vi.restoreAllMocks());

describe("assertSafeUrl", () => {
  it("allows a public host on 443", async () => {
    mockNet({ "example.com": ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"] });
    await expect(assertSafeUrl(new URL("https://example.com/"))).resolves.toBeUndefined();
  });

  it.each([
    ["ftp://example.com/", "http and https"],
    ["https://user:pw@example.com/", "credentials"],
    ["https://example.com:8443/", "ports 80 and 443"],
    ["http://example.com:22/", "ports 80 and 443"],
    ["http://localhost/", "public hostname"],
    ["http://intranet/", "public hostname"],
  ])("refuses %s", async (url, why) => {
    mockNet({ "example.com": ["93.184.215.14"] });
    await expect(assertSafeUrl(new URL(url))).rejects.toThrow(why);
  });

  it.each([
    "http://127.0.0.1/",
    "http://10.1.2.3/",
    "http://192.168.0.1/",
    "http://172.16.5.4/",
    "http://100.64.0.1/", // CGNAT
    "http://169.254.169.254/latest/meta-data/", // cloud metadata
    "http://224.0.0.1/", // multicast
    "http://0.0.0.0/",
    "http://2130706433/", // 127.0.0.1 as a decimal integer
    "http://0x7f000001/",
    "http://[::1]/",
    "http://[fe80::1]/",
    "http://[fd00:ec2::254]/", // AWS IMDS over IPv6
    "http://[::ffff:127.0.0.1]/",
    "http://[64:ff9b::a00:1]/", // NAT64 of 10.0.0.1
    "http://[ff02::1]/",
  ])("refuses literal non-public address %s", async (url) => {
    mockNet({});
    await expect(assertSafeUrl(new URL(url))).rejects.toBeInstanceOf(BlockedUrlError);
  });

  it("refuses a name that resolves to a private address", async () => {
    mockNet({ "evil.test": ["10.0.0.5"] });
    await expect(assertSafeUrl(new URL("https://evil.test/"))).rejects.toThrow("non-public");
  });

  it("refuses if any one of several addresses is private", async () => {
    mockNet({ "mixed.test": ["93.184.215.14", "fd12::1"] });
    await expect(assertSafeUrl(new URL("https://mixed.test/"))).rejects.toThrow("non-public");
  });

  it("refuses a name that doesn't resolve", async () => {
    mockNet({});
    await expect(assertSafeUrl(new URL("https://nxdomain.test/"))).rejects.toThrow("does not resolve");
  });
});

describe("safeFetch", () => {
  it("follows up to 3 redirects, checking each hop", async () => {
    mockNet(
      { "a.test": ["93.184.215.14"], "b.test": ["93.184.215.15"] },
      {
        "https://a.test/": redirect("https://b.test/1"),
        "https://b.test/1": redirect("/2"),
        "https://b.test/2": redirect("https://a.test/3"),
        "https://a.test/3": () => new Response("done"),
      },
    );
    const { response, url } = await safeFetch("https://a.test/");
    expect(url).toBe("https://a.test/3");
    expect(await response.text()).toBe("done");
  });

  it("stops after 3 redirects", async () => {
    mockNet(
      { "a.test": ["93.184.215.14"] },
      {
        "https://a.test/0": redirect("/1"),
        "https://a.test/1": redirect("/2"),
        "https://a.test/2": redirect("/3"),
        "https://a.test/3": redirect("/4"),
      },
    );
    await expect(safeFetch("https://a.test/0")).rejects.toThrow("More than 3 redirects");
  });

  it("can return at the redirect cap instead of throwing, still without fetching the next hop", async () => {
    const spy = mockNet(
      { "a.test": ["93.184.215.14"] },
      { "https://a.test/0": redirect("/1"), "https://a.test/1": redirect("/2"), "https://a.test/2": redirect("/3"), "https://a.test/3": redirect("/4") },
    );
    const res = await safeFetch("https://a.test/0", { returnAtRedirectLimit: true });
    expect(res.redirectLimitHit).toBe(true);
    expect(res.hops.map((h) => h.url)).toEqual(["https://a.test/0", "https://a.test/1", "https://a.test/2", "https://a.test/3"]);
    expect(spy.mock.calls.some(([u]) => String(u).endsWith("/4"))).toBe(false);
  });

  it("refuses a redirect to a private address without fetching it", async () => {
    const spy = mockNet({ "a.test": ["93.184.215.14"] }, { "https://a.test/": redirect("http://169.254.169.254/") });
    await expect(safeFetch("https://a.test/")).rejects.toThrow("Cloud metadata");
    expect(spy.mock.calls.some(([u]) => String(u).includes("169.254"))).toBe(false);
  });

  it("refuses a redirect to a name that resolves privately", async () => {
    mockNet(
      { "a.test": ["93.184.215.14"], "inside.test": ["192.168.1.1"] },
      { "https://a.test/": redirect("https://inside.test/admin") },
    );
    await expect(safeFetch("https://a.test/")).rejects.toThrow("non-public");
  });

  it("times out", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(
      (_input, init) =>
        new Promise((_, reject) => init?.signal?.addEventListener("abort", () => reject(init.signal!.reason))),
    );
    await expect(safeFetch("https://slow.test/", { timeoutMs: 50 })).rejects.toThrow();
  });
});
