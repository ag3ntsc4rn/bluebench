import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { sha256Hex, type ApiError, type SavedDomain } from "@bluebench/shared";
import { eq } from "drizzle-orm";
import { db } from "../src/auth.ts";
import { badgeSvg, publicGrade } from "../src/badge.ts";
import { domain } from "../src/db/schema.ts";
import type { Env } from "../src/env.ts";
import { sharedDomain, sharePage } from "../src/share.ts";
import { call, mockServices, signIn } from "./account.ts";

afterEach(() => vi.restoreAllMocks());

const json = async <T>(res: Response) => (await res.json()) as T;
let n = 0;
const uniq = () => `share${n++}-${Date.now()}.example`;

/** A stand-in for the pre-rendered domain-checker.html (the assets binding), in the shape prerender.tsx writes. */
const TEMPLATE = `<!doctype html><html><head><title>Domain security checker | Bluebench</title>
<meta name="description" content="generic" />
<link rel="canonical" href="https://bluebench.dev/domain-checker" />
<meta property="og:title" content="generic" />
<meta property="og:description" content="generic" />
<meta property="og:url" content="https://bluebench.dev/domain-checker" />
</head><body><div id="root"></div></body></html>`;

function withAssets(): { e: Env; asked: string[] } {
  const asked: string[] = [];
  const ASSETS = {
    fetch: async (req: Request) => {
      const path = new URL(req.url).pathname;
      asked.push(path);
      return path === "/domain-checker" ? new Response(TEMPLATE, { headers: { "content-type": "text/html" } }) : new Response("not found page", { status: 404 });
    },
  } as unknown as Env["ASSETS"];
  return { e: { ...env, ASSETS }, asked };
}

const get = (e: Env, path: string, method = "GET") => sharePage(new Request(`https://bluebench.dev${path}`, { method }), e);

describe("share links", () => {
  it("takes only a single valid domain from the path", () => {
    expect(sharedDomain("/domain-checker/Example.COM")).toBe("example.com");
    expect(sharedDomain("/domain-checker/example.com/")).toBe("example.com");
    expect(sharedDomain("/domain-checker/a/b")).toBeNull();
    expect(sharedDomain("/domain-checker/203.0.113.7")).toBeNull();
    expect(sharedDomain("/domain-checker/%E0%A4%A")).toBeNull(); // malformed escape
    expect(sharedDomain("/domain-checker/")).toBeNull();
  });

  it("serves the checker page with the domain's title, preview tags and noindex", async () => {
    const { e } = withAssets();
    const name = uniq();
    const res = await get(e, `/domain-checker/${name}`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(`<title>${name} security report card | Bluebench</title>`);
    expect(html).toContain(`<meta property="og:url" content="https://bluebench.dev/domain-checker/${name}" />`);
    expect(html).toContain('<meta name="robots" content="noindex" />');
    expect(html).not.toContain('rel="canonical"');
    expect(html).not.toContain('content="generic"');
    expect(res.headers.get("content-security-policy")).toBeTruthy();
    expect(res.headers.get("cache-control")).toBe("public, max-age=300");
  });

  it("shows the grade in the preview when a report is cached, without running a check", async () => {
    const { e } = withAssets();
    const name = uniq();
    await env.VERDICTS.put(`report:v2:${await sha256Hex(name)}`, JSON.stringify({ grade: "B" }));
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const html = await (await get(e, `/domain-checker/${name}`)).text();
    expect(html).toContain(`<title>${name}: grade B | Bluebench</title>`);
    expect(html).toContain(`${name} scored B on email authentication`);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("redirects to the canonical lower-case name, and hands anything else to the 404 page", async () => {
    const { e, asked } = withAssets();
    const moved = await get(e, "/domain-checker/Example.COM");
    expect(moved.status).toBe(301);
    expect(moved.headers.get("location")).toBe("https://bluebench.dev/domain-checker/example.com");

    const bad = await get(e, "/domain-checker/not a domain");
    expect(bad.status).toBe(404);
    expect(asked.at(-1)).toBe("/domain-checker/not%20a%20domain");
  });

  it("answers HEAD without a body", async () => {
    const { e } = withAssets();
    const res = await get(e, `/domain-checker/${uniq()}`, "HEAD");
    expect(res.status).toBe(200);
    expect(res.body).toBeNull();
  });
});

describe("grade badges", () => {
  it("draws each grade with its label, and a neutral badge otherwise", () => {
    expect(badgeSvg("A")).toContain('aria-label="Bluebench grade: A"');
    expect(badgeSvg("A")).toContain("#6CB4FF");
    expect(badgeSvg("C")).toContain("#F5A524");
    expect(badgeSvg("F")).toContain("#FF8A6B");
    expect(badgeSvg(null)).toContain(">not public<");
  });

  it("shows a grade only once the owner verified the domain and published the badge", async () => {
    const svc = mockServices();
    const name = uniq();
    const owner = await signIn(svc.mails);
    const other = await signIn(svc.mails);
    const saved = (await json<{ domain: SavedDomain }>(await call("POST", "/api/domains", { body: { domain: name }, cookie: owner.cookie }))).domain;
    expect(saved.badgePublic).toBe(false);
    await db(env).update(domain).set({ grade: "B", score: 80 }).where(eq(domain.id, saved.id));

    const badge = async () => (await call("GET", `/api/badge/${name}.svg`)).text();
    const publish = (cookie: string, badgePublic = true) => call("PATCH", `/api/domains/${saved.id}`, { body: { badgePublic }, cookie });

    // Not verified: refused, and the badge stays neutral.
    const early = await publish(owner.cookie);
    expect(early.status).toBe(400);
    expect((await json<ApiError>(early)).message).toContain("Verify");
    expect(await badge()).toContain("not public");

    await db(env).update(domain).set({ verifiedAt: new Date() }).where(eq(domain.id, saved.id));
    expect((await publish(other.cookie)).status).toBe(404); // someone else's domain
    const ok = await publish(owner.cookie);
    expect(ok.status).toBe(200);
    expect((await json<{ domain: SavedDomain }>(ok)).domain.badgePublic).toBe(true);

    const res = await call("GET", `/api/badge/${name}.svg`);
    expect(res.headers.get("content-type")).toBe("image/svg+xml; charset=utf-8");
    expect(res.headers.get("cache-control")).toBe("public, max-age=3600");
    expect(await res.text()).toContain("Bluebench grade: B");

    // Losing verification hides it again (once the edge cache's hour is up).
    expect(await publicGrade(env, name)).toBe("B");
    await db(env).update(domain).set({ verifiedAt: null }).where(eq(domain.id, saved.id));
    expect(await publicGrade(env, name)).toBeNull();
  });

  it("refuses paths that aren't a domain's badge", async () => {
    expect((await call("GET", "/api/badge/example.com")).status).toBe(404);
    expect((await call("GET", "/api/badge/203.0.113.7.svg")).status).toBe(404);
  });
});
