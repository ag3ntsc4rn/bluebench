import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { BUILD_VERSION } from "../lib/version";
import { SOURCE_URL } from "../routes";
import { SettingsPage } from "./SettingsPage";

describe("build version", () => {
  it("is a git short SHA and commit date, injected by vite.config.ts", () => {
    expect(BUILD_VERSION.sha).toMatch(/^[0-9a-f]{7,12}$/);
    expect(BUILD_VERSION.date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(BUILD_VERSION.url).toBe(`${SOURCE_URL}/commit/${BUILD_VERSION.sha}`);
  });

  it("is shown on the Settings page, linking to the commit", () => {
    const html = renderToString(<SettingsPage />).replace(/<!-- -->/g, "");
    expect(html).toMatch(new RegExp(`Version <a href="${SOURCE_URL}/commit/${BUILD_VERSION.sha}"[^>]*><span class="font-mono">${BUILD_VERSION.sha}</span></a> \\(${BUILD_VERSION.date}\\)`));
  });
});
