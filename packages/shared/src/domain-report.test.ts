import { describe, expect, it } from "vitest";
import { canonicalDomain, gradeChecks, type CheckId, type CheckStatus } from "./domain-report.ts";

const c = (id: CheckId, status: CheckStatus) => ({ id, status });

describe("canonicalDomain", () => {
  it("normalizes case, trailing dots and IDNs", () => {
    expect(canonicalDomain("Example.COM.")).toBe("example.com");
    expect(canonicalDomain(" mail.example.co.uk ")).toBe("mail.example.co.uk");
    expect(canonicalDomain("bücher.de")).toBe("xn--bcher-kva.de");
  });
  it.each(["", "localhost", "192.0.2.1", "[2001:db8::1]", "example", "http://example.com/", "a b.com"])("rejects %j", (s) => {
    expect(canonicalDomain(s)).toBeNull();
  });
});

describe("gradeChecks", () => {
  const allPass: CheckId[] = ["spf", "dmarc", "dkim", "dnssec", "https", "hsts", "headers", "cert"];

  it("gives an A when everything passes", () => {
    expect(gradeChecks(allPass.map((id) => c(id, "pass")))).toEqual({ score: 100, grade: "A" });
  });

  it("gives half credit for warnings", () => {
    // DMARC (20) warn → loses 10 points.
    expect(gradeChecks(allPass.map((id) => c(id, id === "dmarc" ? "warn" : "pass")))).toEqual({ score: 90, grade: "A" });
  });

  it("drops ungraded checks from the total instead of counting them as failures", () => {
    const checks = [c("mx", "info"), c("spf", "pass"), c("dmarc", "pass"), c("dkim", "info"), c("cert", "skipped")];
    expect(gradeChecks(checks)).toEqual({ score: 100, grade: "A" });
  });

  it("fails a domain with no email or web protection", () => {
    expect(gradeChecks(allPass.map((id) => c(id, "fail"))).grade).toBe("F");
  });

  it("maps scores to letters at 90/80/70/60", () => {
    // Weights: spf 15, dmarc 20 → possible 35.
    expect(gradeChecks([c("spf", "pass"), c("dmarc", "warn")])).toEqual({ score: 71, grade: "C" });
  });
});
