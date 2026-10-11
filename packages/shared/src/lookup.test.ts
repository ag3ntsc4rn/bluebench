import { describe, expect, it } from "vitest";
import {
  cacheKey,
  canonicalIndicator,
  ipRateKey,
  LookupRequestSchema,
  mergeVerdict,
  type SourceResult,
  type SourceStatus,
} from "./lookup.ts";

const result = (status: SourceStatus): SourceResult => ({ source: "urlhaus", status, summary: "", facts: [] });

describe("LookupRequestSchema", () => {
  it("accepts a known kind and value", () => {
    expect(LookupRequestSchema.safeParse({ kind: "domain", value: "example.com" }).success).toBe(true);
  });

  it.each([
    { kind: "jwt", value: "a.b.c" },
    { kind: "domain", value: "" },
    { kind: "url", value: `http://x.com/${"a".repeat(2100)}` },
    { kind: "domain", value: "example.com", extra: 1 },
    { kind: "domain" },
  ])("rejects %j", (body) => {
    expect(LookupRequestSchema.safeParse(body).success).toBe(false);
  });
});

describe("canonicalIndicator", () => {
  it("returns the normalized, refanged value", () => {
    expect(canonicalIndicator({ kind: "domain", value: "Example[.]COM" })).toBe("example.com");
    expect(canonicalIndicator({ kind: "url", value: "hxxps://evil[.]test/a" })).toBe("https://evil.test/a");
    expect(canonicalIndicator({ kind: "md5", value: "D41D8CD98F00B204E9800998ECF8427E" })).toBe(
      "d41d8cd98f00b204e9800998ecf8427e",
    );
    expect(canonicalIndicator({ kind: "ipv6", value: "2606:4700:0:0:0:0:0:1111" })).toBe("2606:4700::1111");
  });

  it("rejects a value that isn't the claimed kind", () => {
    expect(canonicalIndicator({ kind: "sha256", value: "example.com" })).toBeNull();
    expect(canonicalIndicator({ kind: "domain", value: "not a domain" })).toBeNull();
  });

  it.each(["10.0.0.1", "127.0.0.1", "169.254.169.254", "100.64.1.1"])("rejects non-public IPv4 %s", (ip) => {
    expect(canonicalIndicator({ kind: "ipv4", value: ip })).toBeNull();
  });

  it.each(["::1", "fe80::1", "fd00::1", "::ffff:10.0.0.1"])("rejects non-public IPv6 %s", (ip) => {
    expect(canonicalIndicator({ kind: "ipv6", value: ip })).toBeNull();
  });
});

describe("mergeVerdict", () => {
  it("is listed if any source lists it", () => {
    expect(mergeVerdict([result("not-listed"), result("listed"), result("error")])).toBe("listed");
  });
  it("is not-listed only when every source answered", () => {
    expect(mergeVerdict([result("not-listed"), result("not-listed")])).toBe("not-listed");
  });
  it("is incomplete when a source was skipped or failed", () => {
    expect(mergeVerdict([result("not-listed"), result("skipped")])).toBe("incomplete");
    expect(mergeVerdict([result("error")])).toBe("incomplete");
  });
});

describe("ipRateKey", () => {
  it("keys IPv4 per address", () => {
    expect(ipRateKey("203.0.113.7")).toBe("v4:203.0.113.7");
  });
  it("groups IPv6 by /64", () => {
    const a = ipRateKey("2001:db8:1:2:aaaa::1");
    expect(a).toBe("v6:20010db800010002/64");
    expect(ipRateKey("2001:db8:1:2:ffff:ffff:ffff:ffff")).toBe(a);
    expect(ipRateKey("2001:db8:1:3::1")).not.toBe(a);
  });
  it("falls back for garbage", () => {
    expect(ipRateKey("")).toBe("unknown");
  });
});

describe("cacheKey", () => {
  it("hashes kind and value, never containing the indicator", async () => {
    const key = await cacheKey("domain", "example.com");
    expect(key).toMatch(/^v1:[0-9a-f]{64}$/);
    expect(key).not.toContain("example");
    expect(await cacheKey("domain", "example.com")).toBe(key);
    expect(await cacheKey("url", "example.com")).not.toBe(key);
  });
});
