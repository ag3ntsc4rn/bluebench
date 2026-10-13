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
    expect(html).toContain("https://sslmate.com/policies/privacy");
    expect(html).toContain("never scans ports");
    expect(html).toContain("Domain reports");
  });

  it("names the cookies we set", () => {
    expect(html).toContain("__Host-bb_session");
    expect(html).toContain("__Secure-bb.session_token");
  });

  it("explains accounts: what's stored, who delivers alerts, and how to delete it", () => {
    expect(html).toContain("Accounts and alerts (optional)");
    expect(html).toContain("https://resend.com/legal/privacy-policy");
    expect(html).toContain("180 days");
    expect(html).toContain("Delete account");
    expect(html).toContain("encrypted for your device");
  });

  it("explains own API keys: kept in the browser, which go direct and which through our server", () => {
    expect(html).toContain("Your own API keys (optional)");
    expect(html).toContain("IndexedDB");
    expect(html).toContain("https://otx.alienvault.com/privacy-policy");
    expect(html).toContain("passes them on and returns the answer");
  });

  it("lists the watchlist among what an account stores", () => {
    expect(html).toContain("The vendors and products you watch");
  });

  it("says the Intel tab's search stays in the browser", () => {
    expect(html).toContain("searching the list happens in your browser");
  });

  it("mentions the daily lookalike lookups", () => {
    expect(html).toContain("lookalike");
  });

  it("never uses inline style attributes (CSP forbids them)", () => {
    expect(html).not.toMatch(/\sstyle="/);
  });
});
