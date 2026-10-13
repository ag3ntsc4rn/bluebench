import { describe, expect, it } from "vitest";
import { TLDS } from "./tlds.ts";

describe("TLDS", () => {
  it("holds IANA's root zone list, lowercased", () => {
    expect(TLDS.size).toBeGreaterThan(1400);
    for (const t of ["com", "net", "org", "uk", "dev", "top", "xyz", "zip", "xn--p1ai"]) expect(TLDS.has(t), t).toBe(true);
    expect(TLDS.has("cgi")).toBe(false);
    expect(TLDS.has("COM")).toBe(false);
  });
});
