import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { App } from "./App";

describe("App", () => {
  it("renders the five-tab nav with Lookup active", () => {
    const html = renderToString(<App />);
    for (const label of ["Lookup", "Domains", "Alerts", "Respond", "Learn"]) {
      expect(html).toContain(`<span>${label}</span>`);
    }
    expect(/<nav[\s\S]*<\/nav>/.exec(html)![0].match(/<button/g)).toHaveLength(5);
    expect(html).toMatch(/aria-current="page"[^>]*>.*?<span>Lookup<\/span>/);
    expect(html).toContain('for="paste"');
  });

  it("marks only Learn as coming soon", () => {
    expect(renderToString(<App initialTab="learn" />)).toContain("Coming soon.");
    expect(renderToString(<App />).match(/Soon<\/span>/g)).toHaveLength(1);
  });

  it("serves the Respond tab and each runbook under it", () => {
    const index = renderToString(<App initialPath="/respond" />);
    expect(index).toContain('id="respond-heading"');
    expect(index).toMatch(/aria-current="page"[^>]*>.*?<span>Respond<\/span>/);
    expect(index).toContain('href="/respond/ransomware"');

    const page = renderToString(<App initialPath="/respond/phishing-link-clicked" />);
    expect(page).toContain(">Someone clicked a phishing link</h1>");
    expect(page).toMatch(/aria-current="page"[^>]*>.*?<span>Respond<\/span>/);
    expect(page).toContain("data-runbook-step");
    expect(page).toContain('href="/ioc-lookup"');
  });

  it("links to the privacy policy from every tab", () => {
    expect(renderToString(<App />)).toMatch(/<a href="\/privacy"[^>]*>Privacy<\/a>/);
    expect(renderToString(<App initialTab="domains" />)).toContain('href="/privacy"');
  });

  it("serves the privacy policy at /privacy, with no tab marked current", () => {
    const html = renderToString(<App initialPath="/privacy" />);
    expect(html).toContain('id="privacy-heading"');
    expect(html).not.toContain('aria-current="page"');
    expect(html).toContain('href="/jwt-decoder"'); // tool links in the footer everywhere
  });

  it("serves each tool page under the Lookup tab, with its own heading and an example", () => {
    const html = renderToString(<App initialPath="/email-header-analyzer" />);
    expect(html).toContain(">Email header analyzer</h1>");
    expect(html).toContain("Try an example");
    expect(html).toMatch(/aria-current="page"[^>]*>.*?<span>Lookup<\/span>/);
  });

  it("shows a not-found page for unknown paths", () => {
    const html = renderToString(<App initialPath="/nope" />);
    expect(html).toContain("Page not found");
    expect(html).not.toContain('aria-current="page"');
  });

  it("gives the Domains tab its own page at /domain-checker", () => {
    const html = renderToString(<App initialPath="/domain-checker" />);
    expect(html).toContain(">Domain security checker</h1>");
    expect(html).toMatch(/aria-current="page"[^>]*>.*?<span>Domains<\/span>/);
    expect(renderToString(<App />)).toContain('href="/domain-checker"'); // footer link
  });

  it("gives the Alerts tab its own page at /alerts", () => {
    const html = renderToString(<App initialPath="/alerts" />);
    expect(html).toContain('id="alerts-heading"');
    expect(html).toMatch(/aria-current="page"[^>]*>.*?<span>Alerts<\/span>/);
  });

  it("serves the magic-link landing page at /signin, outside the tabs", () => {
    const html = renderToString(<App initialPath="/signin" />);
    expect(html).toContain('id="signin-heading"');
    expect(html).not.toContain('aria-current="page"');
  });

  it("serves About and Settings outside the tabs, and links to both from every page", () => {
    const about = renderToString(<App initialPath="/about" />);
    expect(about).toContain('id="about-heading"');
    expect(about).not.toContain('aria-current="page"');

    const settings = renderToString(<App initialPath="/settings" />);
    expect(settings).toContain('id="settings-heading"');
    expect(settings).toContain("Your API keys");
    expect(settings.match(/href="\/settings" aria-label="Settings" aria-current="page"/)).not.toBeNull();

    for (const html of [renderToString(<App />), renderToString(<App initialPath="/domain-checker" />)]) {
      expect(html).toContain('aria-label="Settings"'); // top bar on mobile
      expect(html).toMatch(/<a href="\/about"[^>]*>About<\/a>/);
      expect(html).toContain('href="https://github.com/ag3ntsc4rn/bluebench"');
      expect(html).toMatch(/<a href="https:\/\/github\.com\/sponsors\/ag3ntsc4rn"[^>]*>Donate<\/a>/);
    }
  });
});
