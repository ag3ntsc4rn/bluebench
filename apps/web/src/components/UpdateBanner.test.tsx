import { renderToString } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { App } from "../App";
import { pwaUpdate } from "../pwa-update";

describe("pwa update store", () => {
  it("notifies subscribers and applies the waiting update", () => {
    const listener = vi.fn();
    const apply = vi.fn();
    const unsubscribe = pwaUpdate.subscribe(listener);
    expect(pwaUpdate.isReady()).toBe(false);

    pwaUpdate.setReady(apply);
    expect(listener).toHaveBeenCalledOnce();
    expect(pwaUpdate.isReady()).toBe(true);

    pwaUpdate.apply();
    expect(apply).toHaveBeenCalledOnce();
    unsubscribe();
  });
});

describe("UpdateBanner", () => {
  it("renders nothing on the server (no update known yet)", () => {
    expect(renderToString(<App />)).not.toContain("A new version of Bluebench is ready.");
  });
});
