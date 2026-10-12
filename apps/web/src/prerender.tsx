import { renderToString } from "react-dom/server";
import { App } from "./App";
import { ABOUT, ALERTS, DOMAINS, HOME, NOT_FOUND, PRIVACY, SETTINGS, SIGNIN, SITE_NAME, SITE_URL, TOOLS, type PageMeta } from "./routes";

/** Build-time only: turns each route into a static HTML file, so crawlers and link previews see real content. */

export interface PrerenderedPage {
  /** Output file in dist, e.g. "jwt-decoder.html" (served at /jwt-decoder). */
  file: string;
  html: string;
  /** Listed in sitemap.xml (everything except the 404, sign-in and settings pages). */
  inSitemap: boolean;
  path: string;
}

export const OG_IMAGE = `${SITE_URL}/og.png`;

const escapeAttr = (s: string) => s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const escapeText = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export function headTags(meta: PageMeta, { indexable }: { indexable: boolean }): string {
  const url = `${SITE_URL}${meta.path === "/" ? "/" : meta.path}`;
  const tags = [
    `<meta name="description" content="${escapeAttr(meta.description)}" />`,
    indexable ? `<link rel="canonical" href="${url}" />` : `<meta name="robots" content="noindex" />`,
    `<meta property="og:type" content="website" />`,
    `<meta property="og:site_name" content="${SITE_NAME}" />`,
    `<meta property="og:title" content="${escapeAttr(meta.title)}" />`,
    `<meta property="og:description" content="${escapeAttr(meta.description)}" />`,
    `<meta property="og:url" content="${url}" />`,
    `<meta property="og:image" content="${OG_IMAGE}" />`,
    `<meta property="og:image:width" content="1200" />`,
    `<meta property="og:image:height" content="630" />`,
    `<meta property="og:image:alt" content="Bluebench: free, open-source security toolkit" />`,
    `<meta name="twitter:card" content="summary_large_image" />`,
  ];
  return tags.join("\n    ");
}

/** Fill the built index.html template for one page. */
export function renderDocument(template: string, meta: PageMeta, body: string, { indexable }: { indexable: boolean }): string {
  const descRe = /<meta name="description" content="[^"]*" \/>/;
  if (!descRe.test(template) || !template.includes('<div id="root"></div>') || !/<title>[^<]*<\/title>/.test(template)) {
    throw new Error("index.html template is missing the description, title or root placeholder");
  }
  return template
    .replace(/<title>[^<]*<\/title>/, () => `<title>${escapeText(meta.title)}</title>`)
    .replace(descRe, () => headTags(meta, { indexable }))
    .replace('<div id="root"></div>', () => `<div id="root">${body}</div>`);
}

export function prerenderPages(template: string): PrerenderedPage[] {
  const page = (meta: PageMeta, file: string, indexable = true): PrerenderedPage => ({
    file,
    path: meta.path,
    inSitemap: indexable,
    html: renderDocument(template, meta, renderToString(<App initialPath={meta.path} />), { indexable }),
  });
  return [
    page(HOME, "index.html"),
    page(PRIVACY, "privacy.html"),
    page(ABOUT, "about.html"),
    ...TOOLS.map((t) => page(t, `${t.slug}.html`)),
    page(DOMAINS, "domain-checker.html"),
    page(ALERTS, "alerts.html"),
    page(SIGNIN, "signin.html", false),
    page(SETTINGS, "settings.html", false),
    page(NOT_FOUND, "404.html", false),
  ];
}

export function sitemap(pages: readonly PrerenderedPage[]): string {
  const urls = pages
    .filter((p) => p.inSitemap)
    .map((p) => `  <url><loc>${SITE_URL}${p.path}</loc></url>`)
    .join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`;
}
