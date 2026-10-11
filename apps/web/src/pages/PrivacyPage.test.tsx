import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { PrivacyPage, PRIVACY_CONTACT } from "./PrivacyPage";

const html = renderToString(<PrivacyPage />).replace(/<!-- -->/g, "");

describe("PrivacyPage", () => {
  it("references Cloudflare's Turnstile Privacy Addendum (required for invisible mode)", () => {
    expect(html).toMatch(/<a href="https:\/\/www\.cloudflare\.com\/turnstile-privacy-policy\/"[^>]*>Cloudflare Turnstile Privacy Addendum<\/a>/);
  });

  it("names the third parties lookups go to, and a contact", () => {
    expect(html).toContain("https://abuse.ch/privacy-policy/");
    expect(html).toContain("https://policies.google.com/privacy");
    expect(html).toContain(`mailto:${PRIVACY_CONTACT}`);
  });

  it("explains what a domain check contacts and stores", () => {
    expect(html).toContain("Check domain");
    expect(html).toContain("https://www.sectigo.com/privacy-policy");
    expect(html).toContain("never scans ports");
    expect(html).toContain("Domain reports");
  });

  it("names the one cookie we set", () => {
    expect(html).toContain("__Host-bb_session");
  });

  it("never uses inline style attributes (CSP forbids them)", () => {
    expect(html).not.toMatch(/\sstyle="/);
  });
});
