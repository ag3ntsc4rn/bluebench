import { describe, expect, it } from "vitest";

const workflows = import.meta.glob<string>("../../../.github/workflows/*.yml", { query: "?raw", import: "default", eager: true });

describe("GitHub Actions workflows", () => {
  it("are found", () => {
    expect(Object.keys(workflows).length).toBeGreaterThanOrEqual(3);
  });

  // A tag can be moved to different code; a commit SHA can't. Dependabot keeps the pins and comments current.
  it("pin every action to a full commit SHA, with its version in a comment", () => {
    for (const [file, text] of Object.entries(workflows)) {
      for (const line of text.split("\n").filter((l) => /^\s*(-\s+)?uses:/.test(l))) {
        expect(line, file).toMatch(/uses: [\w.-]+\/[\w./-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+/);
      }
    }
  });
});
