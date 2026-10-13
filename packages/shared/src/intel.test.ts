import { describe, expect, it } from "vitest";
import { buildKevDocument, firstAdvisory, KEV_MIN_ENTRIES, matchesKev, parseEpssCsv, plainAction, recentKev } from "./intel.ts";

const raw = (i: number, extra: object = {}) => ({
  cveID: `CVE-2026-${String(10000 + i)}`,
  vendorProject: "Fortinet",
  product: "FortiOS",
  vulnerabilityName: "Fortinet FortiOS Heap Overflow",
  dateAdded: `2026-10-${String((i % 28) + 1).padStart(2, "0")}`,
  shortDescription: "A heap overflow lets a remote attacker run code.",
  requiredAction: "Apply mitigations per vendor instructions.",
  dueDate: "2026-11-01",
  knownRansomwareCampaignUse: i % 2 ? "Known" : "Unknown",
  notes: "Please see: https://fortiguard.example/psirt/FG-IR-26-001 ; https://nvd.nist.gov/vuln/detail/CVE-2026-1",
  ...extra,
});
const catalog = (n: number, extra: (i: number) => object = () => ({})) => ({
  catalogVersion: "2026.10.12",
  vulnerabilities: Array.from({ length: n }, (_, i) => raw(i, extra(i))),
});
const noEpss = { date: null, scores: new Map() };

describe("parseEpssCsv", () => {
  const csv = "#model_version:v2026.06.15,score_date:2026-10-12T12:00:26Z\ncve,epss,percentile\nCVE-2024-3400,0.99999,1.0\nCVE-1999-0001,0.03351,0.88393\n";

  it("reads the score date and the scores", () => {
    const { date, scores } = parseEpssCsv(csv);
    expect(date).toBe("2026-10-12");
    expect(scores.get("CVE-2024-3400")).toEqual({ epss: 0.99999, percentile: 1 });
  });

  it("keeps only the CVEs asked for", () => {
    expect([...parseEpssCsv(csv, new Set(["CVE-1999-0001"])).scores.keys()]).toEqual(["CVE-1999-0001"]);
  });
});

describe("firstAdvisory", () => {
  it("takes the first https link from KEV's notes", () => {
    expect(firstAdvisory("See: https://vendor.example/a?b=1 ; https://nvd.nist.gov/x")).toBe("https://vendor.example/a?b=1");
    expect(firstAdvisory("no link here")).toBeUndefined();
    expect(firstAdvisory(undefined)).toBeUndefined();
  });
});

describe("buildKevDocument", () => {
  it("trims entries, joins EPSS scores and sorts newest first", () => {
    const epss = { date: "2026-10-12", scores: new Map([["CVE-2026-10001", { epss: 0.9, percentile: 0.99 }]]) };
    const doc = buildKevDocument(catalog(KEV_MIN_ENTRIES), epss, new Date("2026-10-12T14:00:00Z"));
    expect(doc).toMatchObject({ catalogVersion: "2026.10.12", epssDate: "2026-10-12", updatedAt: "2026-10-12T14:00:00.000Z" });
    expect(doc.entries).toHaveLength(KEV_MIN_ENTRIES);
    const one = doc.entries.find((e) => e.cve === "CVE-2026-10001")!;
    expect(one).toEqual({
      cve: "CVE-2026-10001",
      vendor: "Fortinet",
      product: "FortiOS",
      name: "Fortinet FortiOS Heap Overflow",
      added: "2026-10-02",
      description: "A heap overflow lets a remote attacker run code.",
      action: "Apply the vendor's update or mitigation.",
      due: "2026-11-01",
      ransomware: true,
      advisory: "https://fortiguard.example/psirt/FG-IR-26-001",
      epss: 0.9,
      percentile: 0.99,
    });
    const dates = doc.entries.map((e) => e.added);
    expect(dates).toEqual([...dates].sort().reverse());
  });

  it("drops malformed entries", () => {
    const doc = buildKevDocument(catalog(KEV_MIN_ENTRIES + 2, (i) => (i < 2 ? { cveID: "not-a-cve" } : {})), noEpss);
    expect(doc.entries).toHaveLength(KEV_MIN_ENTRIES);
  });

  it("refuses a download that looks broken, so good data isn't replaced", () => {
    expect(() => buildKevDocument(catalog(10), noEpss)).toThrow(/only 10/);
    expect(() => buildKevDocument({ nope: true }, noEpss)).toThrow();
  });
});

describe("matchesKev", () => {
  const [e] = buildKevDocument(catalog(KEV_MIN_ENTRIES), noEpss).entries;
  it("matches vendor, product, CVE or name, ignoring case", () => {
    expect(matchesKev(e!, "forti")).toBe(true);
    expect(matchesKev(e!, "FORTIOS")).toBe(true);
    expect(matchesKev(e!, e!.cve.toLowerCase())).toBe(true);
    expect(matchesKev(e!, "heap overflow")).toBe(true);
    expect(matchesKev(e!, "ivanti")).toBe(false);
    expect(matchesKev(e!, "  ")).toBe(true);
  });
});

describe("recentKev", () => {
  it("keeps entries from the last 90 days only", () => {
    const doc = buildKevDocument(catalog(KEV_MIN_ENTRIES, (i) => ({ dateAdded: i === 0 ? "2026-10-10" : "2026-06-01" })), noEpss, new Date("2026-10-12T14:00:00Z"));
    expect(recentKev(doc).entries.map((e) => e.added)).toEqual(["2026-10-10"]);
    expect(recentKev(doc).catalogVersion).toBe(doc.catalogVersion);
  });
});

describe("plainAction", () => {
  it("turns CISA's federal boilerplate into a plain instruction", () => {
    expect(plainAction("Apply updates per vendor instructions.")).toBe("Apply the vendor's update or mitigation.");
    expect(plainAction("Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.")).toBe(
      "Apply the vendor's update or mitigation. If there isn't one, stop using the product.",
    );
    expect(plainAction("The impacted product is end-of-life and should be disconnected if still in use.")).toContain("end-of-life");
  });

  it("keeps specific instructions as written", () => {
    expect(plainAction("Disable the SSL VPN until patched.")).toBe("Disable the SSL VPN until patched.");
  });
});
