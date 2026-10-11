import { describe, expect, it } from "vitest";
import { prerenderPages, sitemap } from "./prerender";
import { TOOLS } from "./routes";

const TEMPLATE = `<!doctype html><html><head>
<meta name="description" content="x" />
<title>Bluebench</title></head><body><div id="root"></div></body></html>`;

const pages = prerenderPages(TEMPLATE);
const byFile = Object.fromEntries(pages.map((p) => [p.file, p.html]));

describe("prerender", () => {
  it("writes one file per route plus a 404 page", () => {
    expect(Object.keys(byFile).sort()).toEqual(
      ["index.html", "privacy.html", "404.html", ...TOOLS.map((t) => `${t.slug}.html`)].sort(),
    );
  });

  it("gives each page its own title, description, canonical URL and link-preview tags", () => {
    const html = byFile["jwt-decoder.html"]!;
    expect(html).toContain("<title>JWT decoder: decode and inspect JSON Web Tokens in your browser | Bluebench</title>");
    expect(html).toContain('<link rel="canonical" href="https://bluebench.dev/jwt-decoder" />');
    expect(html).toContain('<meta property="og:image" content="https://bluebench.dev/og.png" />');
    expect(html).toContain('<meta name="twitter:card" content="summary_large_image" />');
    expect(html).toContain('alg &quot;none&quot;'); // attribute escaping
    expect(html.match(/<meta name="description"/g)).toHaveLength(1);
  });

  it("puts real content in the root for crawlers", () => {
    expect(byFile["jwt-decoder.html"]).toMatch(/<div id="root">.*<h1[^>]*>JWT decoder<\/h1>/s);
    expect(byFile["index.html"]).toContain('href="/email-header-analyzer"');
  });

  it("marks the 404 page noindex and leaves it out of the sitemap", () => {
    expect(byFile["404.html"]).toContain('<meta name="robots" content="noindex" />');
    expect(byFile["404.html"]).not.toContain('rel="canonical"');
    const xml = sitemap(pages);
    expect(xml).toContain("<loc>https://bluebench.dev/</loc>");
    expect(xml).toContain("<loc>https://bluebench.dev/url-decoder</loc>");
    expect(xml).not.toContain("404");
  });

  it("never emits inline style attributes (CSP forbids them)", () => {
    for (const [file, html] of Object.entries(byFile)) expect(html, file).not.toMatch(/\sstyle="/);
  });
});
