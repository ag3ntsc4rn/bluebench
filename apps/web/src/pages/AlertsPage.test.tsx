import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { AlertsPage } from "./AlertsPage";
import { SignInPage } from "./SignInPage";

describe("AlertsPage", () => {
  it("pre-renders a heading and explanation, then loads the account in the browser", () => {
    const html = renderToString(<AlertsPage />).replace(/<!-- -->/g, "");
    expect(html).toContain('id="alerts-heading"');
    expect(html).toContain("re-checks them daily");
    expect(html).toContain("Loading…");
    expect(html).not.toMatch(/\sstyle="/);
  });
});

describe("SignInPage", () => {
  it("pre-renders without the token (it's read from the fragment in the browser)", () => {
    const html = renderToString(<SignInPage onDone={() => {}} />);
    expect(html).toContain('id="signin-heading"');
    expect(html).not.toContain("Finish signing in");
  });
});
