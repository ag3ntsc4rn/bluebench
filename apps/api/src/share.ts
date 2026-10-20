import { canonicalDomain, SECURITY_HEADERS, sha256Hex, type DomainReport, type Grade } from "@bluebench/shared";
import { publicGrade } from "./badge.ts";
import type { Env } from "./env.ts";

/**
 * Shareable report links: /domain-checker/<domain>. Serves the pre-rendered domain checker page (which
 * runs the check itself, with the usual bot check and limits) with that domain's title and link-preview
 * tags, so a link pasted into chat shows what it is, and the grade when we already know it. Never runs a
 * check here: the grade comes from a cached report or a badge the owner chose to publish.
 * These pages are noindex and not in the sitemap: Bluebench shouldn't become a searchable list of weak grades.
 */

export const SHARE_PREFIX = "/domain-checker/";

/** The domain in a share path, or null if it isn't one we'd check. */
export function sharedDomain(pathname: string): string | null {
  let raw: string;
  try {
    raw = decodeURIComponent(pathname.slice(SHARE_PREFIX.length)).replace(/\/$/, "");
  } catch {
    return null;
  }
  return raw && !raw.includes("/") ? canonicalDomain(raw) : null;
}

async function knownGrade(env: Env, name: string): Promise<Grade | null> {
  const cached = await env.VERDICTS.get<Pick<DomainReport, "grade">>(`report:v2:${await sha256Hex(name)}`, "json").catch(() => null);
  if (cached?.grade) return cached.grade;
  return publicGrade(env, name).catch(() => null);
}

export function shareMeta(name: string, grade: Grade | null): { title: string; description: string } {
  const checks = "email authentication (SPF, DKIM, DMARC), HTTPS, HSTS, security headers and certificates";
  return grade
    ? { title: `${name}: grade ${grade} | Bluebench`, description: `${name} scored ${grade} on ${checks}. Check any domain free with Bluebench.` }
    : { title: `${name} security report card | Bluebench`, description: `Check ${name}'s ${checks}. Free, with a one-line fix for each problem.` };
}

export async function sharePage(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const name = sharedDomain(url.pathname);
  // The assets binding answers unknown paths with the 404 page and a real 404.
  if (!name) return env.ASSETS.fetch(new Request(url, { method: req.method }));
  const canonical = `${url.origin}${SHARE_PREFIX}${name}`;
  if (url.pathname !== `${SHARE_PREFIX}${name}`) return Response.redirect(canonical, 301);

  const page = await env.ASSETS.fetch(new Request(new URL("/domain-checker", url.origin)));
  if (!page.ok) return page;
  const { title, description } = shareMeta(name, await knownGrade(env, name));
  const content = (value: string) => ({ element: (e: Element) => void e.setAttribute("content", value) });
  const res = new HTMLRewriter()
    .on("title", { element: (e) => void e.setInnerContent(title) })
    .on('meta[name="description"]', content(description))
    .on('meta[property="og:title"]', content(title))
    .on('meta[property="og:description"]', content(description))
    .on('meta[property="og:url"]', content(canonical))
    .on('link[rel="canonical"]', { element: (e) => void e.replace('<meta name="robots" content="noindex" />', { html: true }) })
    .transform(page);

  const headers = new Headers({ "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=300" });
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
  return new Response(req.method === "HEAD" ? null : res.body, { status: 200, headers });
}
