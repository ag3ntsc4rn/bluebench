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

  it("marks Respond and Learn as coming soon", () => {
    expect(renderToString(<App initialTab="learn" />)).toContain("Coming soon.");
    expect(renderToString(<App />).match(/Soon<\/span>/g)).toHaveLength(2);
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
});
