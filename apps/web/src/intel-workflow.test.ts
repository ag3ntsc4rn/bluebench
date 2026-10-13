import { KEV_KV_KEYS } from "@bluebench/shared";
import { describe, expect, it } from "vitest";
import workflow from "../../../.github/workflows/intel.yml?raw";

describe("intel workflow", () => {
  it("writes to the KV keys the API reads", () => {
    for (const key of Object.values(KEV_KV_KEYS)) expect(workflow).toContain(`"${key}"`);
  });
});
