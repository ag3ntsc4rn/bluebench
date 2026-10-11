import { classifyIp, normalizeDomain, parseIp } from "@bluebench/shared";

/**
 * SSRF guard for any server-side fetch to a user-supplied host (domain checks in M4).
 * Resolves DNS first and refuses non-public addresses (v4 and v6), allows only ports 80/443,
 * re-checks every redirect hop (max 3) and gives up after 5 s overall.
 */

export class BlockedUrlError extends Error {}

const DOH_URL = "https://cloudflare-dns.com/dns-query";
const ALLOWED_PORTS = new Set(["", "80", "443"]);
const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_REDIRECTS = 3;

/** A and AAAA addresses for a hostname via DNS-over-HTTPS (Cloudflare 1.1.1.1). */
export async function resolveHost(host: string, signal?: AbortSignal): Promise<string[]> {
  const lookups = ["A", "AAAA"].map(async (type) => {
    const res = await fetch(`${DOH_URL}?name=${encodeURIComponent(host)}&type=${type}`, {
      headers: { accept: "application/dns-json" },
      signal,
    });
    if (!res.ok) throw new BlockedUrlError("DNS lookup failed");
    const data = (await res.json()) as { Status?: number; Answer?: { type: number; data: string }[] };
    if (data.Status !== 0 && data.Status !== 3) throw new BlockedUrlError("DNS lookup failed"); // 3 = NXDOMAIN
    return (data.Answer ?? []).filter((a) => a.type === 1 || a.type === 28).map((a) => a.data);
  });
  return (await Promise.all(lookups)).flat();
}

function assertPublicAddress(address: string): void {
  const ip = parseIp(address);
  if (!ip) throw new BlockedUrlError("Unrecognised address");
  const { global, range } = classifyIp(ip);
  if (!global) throw new BlockedUrlError(`Refusing to connect to a non-public address (${range})`);
}

export type HostResolver = (host: string, signal?: AbortSignal) => Promise<string[]>;

/** Throws BlockedUrlError unless the URL is http(s), on port 80/443, and every address it resolves to is public. */
export async function assertSafeUrl(url: URL, signal?: AbortSignal, resolve: HostResolver = resolveHost): Promise<void> {
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new BlockedUrlError("Only http and https are allowed");
  if (url.username || url.password) throw new BlockedUrlError("URLs with credentials are not allowed");
  if (!ALLOWED_PORTS.has(url.port)) throw new BlockedUrlError("Only ports 80 and 443 are allowed");

  const host = url.hostname.replace(/^\[(.*)\]$/, "$1");
  if (parseIp(host)) return assertPublicAddress(host);
  if (!normalizeDomain(host)) throw new BlockedUrlError("Not a public hostname");
  const addresses = await resolve(host, signal);
  if (addresses.length === 0) throw new BlockedUrlError("Hostname does not resolve");
  addresses.forEach(assertPublicAddress); // every address, so a mixed answer can't sneak a private one in
}

export interface SafeFetchOptions {
  method?: "GET" | "HEAD";
  headers?: HeadersInit;
  timeoutMs?: number;
  maxRedirects?: number;
  /** DNS resolver (default: DoH). Lets a caller share a memoised, budgeted resolver. */
  resolve?: HostResolver;
  /** Called before each outbound fetch (not DNS); throw to stop, e.g. when a request budget is spent. */
  beforeFetch?: () => void;
  /** Return the first response even if it's a redirect, instead of following it. */
  noFollow?: boolean;
}

export interface SafeFetchHop {
  url: string;
  status: number;
  headers: Headers;
}

export interface SafeFetchResult {
  response: Response;
  url: string;
  /** Every response in the chain, first to last (the last is `response`). */
  hops: SafeFetchHop[];
}

/** Fetch with SSRF protection. Returns the final response, the URL it came from and each hop. */
export async function safeFetch(input: string, opts: SafeFetchOptions = {}): Promise<SafeFetchResult> {
  const signal = AbortSignal.timeout(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const maxRedirects = opts.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new BlockedUrlError("Invalid URL");
  }

  const hops: SafeFetchHop[] = [];
  for (let hop = 0; ; hop++) {
    await assertSafeUrl(url, signal, opts.resolve);
    opts.beforeFetch?.();
    const response = await fetch(url, { method: opts.method ?? "GET", headers: opts.headers, redirect: "manual", signal });
    hops.push({ url: url.href, status: response.status, headers: response.headers });
    const location = response.headers.get("location");
    if (response.status < 300 || response.status > 399 || !location || opts.noFollow) return { response, url: url.href, hops };
    if (hop >= maxRedirects) {
      await response.body?.cancel();
      throw new BlockedUrlError(`More than ${maxRedirects} redirects`);
    }
    await response.body?.cancel();
    try {
      url = new URL(location, url);
    } catch {
      throw new BlockedUrlError("Invalid redirect");
    }
  }
}
