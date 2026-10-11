import { describe, expect, it } from "vitest";
import { classifyIp, formatIPv6, parseIp, parseIPv4, parseIPv6 } from "./ip.ts";

const v6 = (s: string) => formatIPv6(parseIPv6(s)!);
const classify = (s: string) => classifyIp(parseIp(s)!);

describe("parseIPv4", () => {
  it("parses dotted quads", () => {
    expect(parseIPv4("0.0.0.0")).toBe(0);
    expect(parseIPv4("255.255.255.255")).toBe(0xffffffff);
    expect(parseIPv4("192.168.1.10")).toBe(0xc0a8010a);
  });

  it.each(["256.1.1.1", "1.2.3", "1.2.3.4.5", "01.2.3.4", "1.2.3.4 ", "a.b.c.d", ""])("rejects %j", (s) => {
    expect(parseIPv4(s)).toBeNull();
  });
});

describe("parseIPv6 / formatIPv6", () => {
  it.each([
    ["::", "::"],
    ["::1", "::1"],
    ["2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"],
    ["2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"],
    ["fe80::1:2", "fe80::1:2"],
    ["::ffff:192.0.2.1", "::ffff:c000:201"],
    ["1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"],
    ["1::", "1::"],
    ["2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"], // single zero group isn't compressed
  ])("%s → %s", (input, expected) => {
    expect(v6(input)).toBe(expected);
  });

  it.each(["1:2:3:4:5:6:7", "1::2::3", "12345::", "1:2:3:4:5:6:7:8:9", "::g", "1.2.3.4", "fe80::1%eth0", ":"])(
    "rejects %j",
    (s) => expect(parseIPv6(s)).toBeNull(),
  );
});

describe("classifyIp", () => {
  it.each([
    ["8.8.8.8", true, "Public"],
    ["10.1.2.3", false, "Private (RFC 1918)"],
    ["172.31.255.255", false, "Private (RFC 1918)"],
    ["172.32.0.1", true, "Public"],
    ["192.168.0.1", false, "Private (RFC 1918)"],
    ["100.64.0.1", false, "Carrier-grade NAT"],
    ["127.0.0.1", false, "Loopback"],
    ["169.254.169.254", false, "Cloud metadata service"],
    ["169.254.1.1", false, "Link-local"],
    ["203.0.113.7", false, "Documentation (TEST-NET-3)"],
    ["224.0.0.251", false, "Multicast"],
    ["255.255.255.255", false, "Broadcast"],
    ["2606:4700:4700::1111", true, "Public"],
    ["::1", false, "Loopback"],
    ["fd12::1", false, "Private (unique local)"],
    ["fe80::1", false, "Link-local"],
    ["ff02::1", false, "Multicast"],
    ["2001:db8::1", false, "Documentation"],
    ["::ffff:127.0.0.1", false, "IPv4-mapped: Loopback"],
    ["::ffff:8.8.8.8", true, "IPv4-mapped: Public"],
    ["64:ff9b::a9fe:a9fe", false, "NAT64: Cloud metadata service"],
    ["4000::1", false, "Reserved"],
  ])("%s", (ip, global, range) => {
    expect(classify(ip)).toEqual({ global, range });
  });
});
