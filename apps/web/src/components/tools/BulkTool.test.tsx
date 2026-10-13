import { describe, expect, it } from "vitest";
import { defangExtracted } from "./BulkTool";

describe("defangExtracted", () => {
  it("makes links, hosts and addresses unclickable, and leaves hashes alone", () => {
    expect(defangExtracted({ kind: "url", value: "https://evil.top/a" })).toBe("hxxps://evil[.]top/a");
    expect(defangExtracted({ kind: "domain", value: "evil.top" })).toBe("evil[.]top");
    expect(defangExtracted({ kind: "ipv4", value: "198.51.100.7" })).toBe("198[.]51[.]100[.]7");
    expect(defangExtracted({ kind: "email", value: "a@evil.top" })).toBe("a@evil[.]top");
    expect(defangExtracted({ kind: "md5", value: "a".repeat(32) })).toBe("a".repeat(32));
  });
});
