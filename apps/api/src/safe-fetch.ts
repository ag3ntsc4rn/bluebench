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

/** Throws BlockedUrlError unless the URL is http(s), on port 80/443, and every address it resolves to is public. */
export async function assertSafeUrl(url: URL, signal?: AbortSignal): Promise<void> {
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new BlockedUrlError("Only http and https are allowed");
  if (url.username || url.password) throw new BlockedUrlError("URLs with credentials are not allowed");
  if (!ALLOWED_PORTS.has(url.port)) throw new BlockedUrlError("Only ports 80 and 443 are allowed");

  const host = url.hostname.replace(/^\[(.*)\]$/, "$1");
  if (parseIp(host)) return assertPublicAddress(host);
  if (!normalizeDomain(host)) throw new BlockedUrlError("Not a public hostname");
  const addresses = await resolveHost(host, signal);
  if (addresses.length === 0) throw new BlockedUrlError("Hostname does not resolve");
  addresses.forEach(assertPublicAddress); // every address, so a mixed answer can't sneak a private one in
}

export interface SafeFetchOptions {
  method?: "GET" | "HEAD";
  headers?: HeadersInit;
  timeoutMs?: number;
  maxRedirects?: number;
}

/** Fetch with SSRF protection. Returns the final response and the URL it came from. */
export async function safeFetch(input: string, opts: SafeFetchOptions = {}): Promise<{ response: Response; url: string }> {
  const signal = AbortSignal.timeout(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const maxRedirects = opts.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new BlockedUrlError("Invalid URL");
  }

  for (let hop = 0; ; hop++) {
    await assertSafeUrl(url, signal);
    const response = await fetch(url, { method: opts.method ?? "GET", headers: opts.headers, redirect: "manual", signal });
    const location = response.headers.get("location");
    if (response.status < 300 || response.status > 399 || !location) return { response, url: url.href };
    if (hop >= maxRedirects) throw new BlockedUrlError(`More than ${maxRedirects} redirects`);
    await response.body?.cancel();
    try {
      url = new URL(location, url);
    } catch {
      throw new BlockedUrlError("Invalid redirect");
    }
  }
}
