import { describe, expect, it } from "vitest";
import { pageForPath } from "./routes";
import { RUNBOOKS, runbookText, stepId } from "./runbooks";

describe("runbooks", () => {
  it("have unique slugs and paths under /respond", () => {
    expect(new Set(RUNBOOKS.map((r) => r.slug)).size).toBe(RUNBOOKS.length);
    for (const r of RUNBOOKS) expect(r.path).toBe(`/respond/${r.slug}`);
  });

  it.each(RUNBOOKS.map((r) => [r.slug, r] as const))("%s: is a complete checklist", (_slug, r) => {
    expect(r.escalate.length).toBeGreaterThan(0);
    expect(r.phases.map((p) => p.heading)).toEqual(["Right now", "Contain", "Investigate", "Recover", "Afterwards"]);
    for (const p of r.phases) expect(p.steps.length).toBeGreaterThan(0);
  });

  it("only link to pages that exist", () => {
    for (const r of RUNBOOKS) {
      for (const step of r.phases.flatMap((p) => p.steps)) {
        if (step.tool) expect(pageForPath(step.tool.path).kind, `${r.slug}: ${step.tool.path}`).not.toBe("notfound");
      }
    }
  });

  it("copy as plain text with the ticked steps marked", () => {
    const r = RUNBOOKS[0]!;
    const text = runbookText(r, new Set([stepId(0, 0)]));
    const lines = text.split("\n");
    expect(lines[0]).toBe(r.h1);
    expect(lines).toContain("Right now:");
    expect(lines).toContain(`[x] ${r.phases[0]!.steps[0]!.do}`);
    expect(lines).toContain(`[ ] ${r.phases[0]!.steps[1]!.do}`);
    expect(text.trimEnd().endsWith(`https://bluebench.dev${r.path}`)).toBe(true);
  });
});
