import { vi } from "vitest";

/** Canned upstream answers keyed by indicator. Anything not listed is "not found". */
export interface UpstreamFixtures {
  urlhausHost?: Record<string, object>;
  urlhausUrl?: Record<string, object>;
  threatfox?: Record<string, object[]>;
  bazaar?: Record<string, object>;
  safeBrowsing?: Record<string, object[]>;
  /** Hostnames to fail with HTTP 500. */
  down?: string[];
}

export type UpstreamCall = { host: string; path: string };

/** Stub global fetch with fake Turnstile, abuse.ch and Safe Browsing endpoints. Returns the call log. */
export function mockUpstream(f: UpstreamFixtures = {}) {
  const calls: UpstreamCall[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const req = new Request(input, init);
    const url = new URL(req.url);
    calls.push({ host: url.hostname, path: url.pathname });
    if (f.down?.includes(url.hostname)) return new Response("oops", { status: 500 });
    switch (url.hostname) {
      case "challenges.cloudflare.com": {
        const form = await req.formData();
        return Response.json({ success: form.get("response") === "good-token" });
      }
      case "urlhaus-api.abuse.ch": {
        if (req.headers.get("auth-key") !== "test-abusech-key") return Response.json({ query_status: "unknown_auth_key" });
        const form = new URLSearchParams(new TextDecoder().decode(await req.arrayBuffer()));
        if (url.pathname === "/v1/host/") {
          const hit = f.urlhausHost?.[form.get("host")!];
          return Response.json(hit ? { query_status: "ok", ...hit } : { query_status: "no_results" });
        }
        if (url.pathname === "/v1/url/") {
          const hit = f.urlhausUrl?.[form.get("url")!];
          return Response.json(hit ? { query_status: "ok", ...hit } : { query_status: "no_results" });
        }
        return Response.json({ query_status: "no_results" });
      }
      case "threatfox-api.abuse.ch": {
        const body = (await req.json()) as { search_term?: string; hash?: string };
        const hit = f.threatfox?.[body.search_term ?? body.hash ?? ""];
        return Response.json(hit ? { query_status: "ok", data: hit } : { query_status: "no_result", data: "no results" });
      }
      case "mb-api.abuse.ch": {
        const form = new URLSearchParams(new TextDecoder().decode(await req.arrayBuffer()));
        const hit = f.bazaar?.[form.get("hash")!];
        return Response.json(hit ? { query_status: "ok", data: [hit] } : { query_status: "hash_not_found" });
      }
      case "safebrowsing.googleapis.com": {
        if (url.searchParams.get("key") !== "test-sb-key") return new Response("denied", { status: 403 });
        const body = (await req.json()) as { threatInfo: { threatEntries: { url: string }[] } };
        const hit = f.safeBrowsing?.[body.threatInfo.threatEntries[0]!.url];
        return Response.json(hit ? { matches: hit } : {});
      }
    }
    throw new Error(`Unexpected outbound fetch to ${url.hostname}`);
  });
  return calls;
}
