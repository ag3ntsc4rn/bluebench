import { describe, expect, it } from "vitest";
import { byoRequest, ByoRequestSchema, byoSourcesFor, parseByo, RELAY_HOSTS, RELAY_SOURCE_IDS } from "./byo.ts";

const KEY = "a".repeat(64);

describe("byoRequest", () => {
  it("builds VirusTotal URLs per kind, with the URL id as unpadded base64url", () => {
    expect(byoRequest("virustotal", "ipv4", "198.51.100.7", KEY).url).toBe("https://www.virustotal.com/api/v3/ip_addresses/198.51.100.7");
    expect(byoRequest("virustotal", "sha256", "ab".repeat(32), KEY).url).toBe(`https://www.virustotal.com/api/v3/files/${"ab".repeat(32)}`);
    // VirusTotal's documented example: base64url("http://www.somedomain.com/this/is/my/url") without padding.
    expect(byoRequest("virustotal", "url", "http://www.somedomain.com/this/is/my/url", KEY).url).toBe(
      "https://www.virustotal.com/api/v3/urls/aHR0cDovL3d3dy5zb21lZG9tYWluLmNvbS90aGlzL2lzL215L3VybA",
    );
    expect(byoRequest("virustotal", "domain", "example.com", KEY).headers).toEqual({ "x-apikey": KEY, accept: "application/json" });
  });

  it("encodes the indicator so it can't change the path", () => {
    expect(byoRequest("otx", "url", "https://e.example/a?b=c", KEY).url).toBe(
      "https://otx.alienvault.com/api/v1/indicators/url/https%3A%2F%2Fe.example%2Fa%3Fb%3Dc/general",
    );
    expect(byoRequest("abuseipdb", "ipv6", "2001:db8::1", KEY).url).toBe("https://api.abuseipdb.com/api/v2/check?ipAddress=2001%3Adb8%3A%3A1&maxAgeInDays=90");
  });

  it("only ever targets the relay's allowed hosts for relayed sources", () => {
    for (const s of RELAY_SOURCE_IDS) expect(RELAY_HOSTS.has(new URL(byoRequest(s, "ipv4", "198.51.100.7", KEY).url).hostname)).toBe(true);
    expect(RELAY_SOURCE_IDS).not.toContain("otx");
  });
});

describe("ByoRequestSchema", () => {
  it("accepts relayed keys only, and rejects anything that isn't key-shaped", () => {
    expect(ByoRequestSchema.safeParse({ kind: "ipv4", value: "198.51.100.7", keys: { virustotal: KEY } }).success).toBe(true);
    expect(ByoRequestSchema.safeParse({ kind: "ipv4", value: "198.51.100.7", keys: { otx: KEY } }).success).toBe(false);
    expect(ByoRequestSchema.safeParse({ kind: "ipv4", value: "198.51.100.7", keys: {} }).success).toBe(false);
    expect(ByoRequestSchema.safeParse({ kind: "ipv4", value: "198.51.100.7", keys: { virustotal: "abc\r\nX-Evil: 1aaaaaaaaaa" } }).success).toBe(false);
  });
});

describe("byoSourcesFor", () => {
  it("picks the sources with a key that can answer the kind", () => {
    const keys = { virustotal: KEY, greynoise: KEY, otx: KEY };
    expect(byoSourcesFor("ipv4", keys)).toEqual(["virustotal", "greynoise", "otx"]);
    expect(byoSourcesFor("ipv6", keys)).toEqual(["virustotal", "otx"]);
    expect(byoSourcesFor("sha1", { abuseipdb: KEY })).toEqual([]);
  });
});

describe("parseByo", () => {
  it("VirusTotal: two or more malicious verdicts list it; one doesn't", () => {
    const vt = (malicious: number) => ({ data: { id: "x", attributes: { last_analysis_stats: { malicious, suspicious: 0, harmless: 60, undetected: 10 }, reputation: -5 } } });
    expect(parseByo("virustotal", "domain", "evil.example", 200, vt(7))).toMatchObject({
      status: "listed",
      summary: "7 security vendors of 77 flag this as malicious.",
      link: "https://www.virustotal.com/gui/domain/x",
    });
    expect(parseByo("virustotal", "domain", "x.example", 200, vt(1))).toMatchObject({ status: "not-listed", summary: expect.stringContaining("false positive") });
    expect(parseByo("virustotal", "md5", "0".repeat(32), 404, null)).toMatchObject({ status: "not-listed" });
  });

  it("AbuseIPDB: listed at 25 % confidence or more, never for allow-listed addresses", () => {
    const ab = (score: number, extra = {}) => ({ data: { abuseConfidenceScore: score, totalReports: 12, isp: "Example ISP", ...extra } });
    expect(parseByo("abuseipdb", "ipv4", "198.51.100.7", 200, ab(100)).status).toBe("listed");
    expect(parseByo("abuseipdb", "ipv4", "198.51.100.7", 200, ab(10)).status).toBe("not-listed");
    expect(parseByo("abuseipdb", "ipv4", "198.51.100.7", 200, ab(100, { isWhitelisted: true })).status).toBe("not-listed");
  });

  it("GreyNoise: malicious is listed; benign and unseen aren't", () => {
    expect(parseByo("greynoise", "ipv4", "198.51.100.7", 200, { noise: true, riot: false, classification: "malicious", last_seen: "2026-10-01" }).status).toBe("listed");
    expect(parseByo("greynoise", "ipv4", "8.8.8.8", 200, { noise: false, riot: true, classification: "benign", name: "Google Public DNS" })).toMatchObject({
      status: "not-listed",
      summary: "A known benign service (Google Public DNS).",
    });
    expect(parseByo("greynoise", "ipv4", "198.51.100.7", 404, { message: "not observed" }).status).toBe("not-listed");
  });

  it("OTX: pulses list it, unless OTX marks it known good", () => {
    const otx = (count: number, validation: object[] = []) => ({ pulse_info: { count, pulses: [{ name: "Campaign A" }] }, validation });
    expect(parseByo("otx", "domain", "evil.example", 200, otx(3))).toMatchObject({ status: "listed", summary: "Appears in 3 community threat pulses." });
    expect(parseByo("otx", "domain", "google.com", 200, otx(50, [{ source: "whitelist", message: "Whitelisted domain google.com" }])).status).toBe("not-listed");
    expect(parseByo("otx", "domain", "quiet.example", 200, otx(0)).status).toBe("not-listed");
  });

  it("explains rejected keys and spent quotas", () => {
    expect(parseByo("virustotal", "ipv4", "198.51.100.7", 401, null)).toMatchObject({ status: "error", summary: expect.stringContaining("didn't accept your API key") });
    expect(parseByo("abuseipdb", "ipv4", "198.51.100.7", 429, null)).toMatchObject({ status: "skipped", summary: expect.stringContaining("quota") });
  });

  it("never throws on junk", () => {
    for (const s of ["virustotal", "abuseipdb", "greynoise", "otx"] as const) {
      expect(() => parseByo(s, "ipv4", "198.51.100.7", 200, "nonsense")).not.toThrow();
      expect(() => parseByo(s, "ipv4", "198.51.100.7", 200, null)).not.toThrow();
    }
  });
});
