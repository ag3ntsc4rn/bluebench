import { vi } from "vitest";

const TYPE_NUM = { A: 1, CNAME: 5, MX: 15, TXT: 16, AAAA: 28 } as const;
type RType = keyof typeof TYPE_NUM;

export interface Zone {
  A?: string[];
  AAAA?: string[];
  MX?: string[];
  /** Unquoted strings; the fake DoH quotes them like a real resolver. */
  TXT?: string[];
  /** DNSSEC-validated (AD flag). */
  ad?: boolean;
  /** Answer SERVFAIL for every type, like a resolver does for broken DNSSEC. */
  servfail?: boolean;
}

export interface Site {
  status?: number;
  headers?: Record<string, string>;
}

export interface FakeNet {
  dns?: Record<string, Zone>;
  /** Keyed by full URL, e.g. "https://example.com/". */
  sites?: Record<string, Site>;
  /** crt.sh JSON rows, or a status code to fail with. */
  crtsh?: object[] | number;
  /** Answer anything else (Resend, push services, …); return undefined to fall through. */
  handle?: (req: Request, url: URL) => Response | undefined | Promise<Response | undefined>;
}

/** Stub fetch with a fake DoH resolver, websites and crt.sh. Returns the log of outbound URLs. */
export function mockNet(net: FakeNet) {
  const calls: string[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const req = new Request(input, init);
    const url = new URL(req.url);
    calls.push(url.href);
    if (url.hostname === "cloudflare-dns.com") {
      const name = url.searchParams.get("name")!.toLowerCase().replace(/\.$/, "");
      const type = url.searchParams.get("type") as RType;
      const zone = net.dns?.[name];
      if (zone?.servfail) return Response.json({ Status: 2, AD: false });
      if (!zone) return Response.json({ Status: 3, AD: false });
      const values = zone[type as "A"] ?? [];
      const Answer = values.map((v) => ({ type: TYPE_NUM[type], data: type === "TXT" ? `"${v}"` : v }));
      return Response.json({ Status: 0, AD: zone.ad ?? false, Answer });
    }
    if (url.hostname === "challenges.cloudflare.com") return Response.json({ success: true });
    if (url.hostname === "crt.sh") {
      if (typeof net.crtsh === "number") return new Response("busy", { status: net.crtsh });
      return Response.json(net.crtsh ?? []);
    }
    const handled = await net.handle?.(req, url);
    if (handled) return handled;
    const site = net.sites?.[url.href];
    if (!site) throw new TypeError("connection refused");
    return new Response("<html></html>", { status: site.status ?? 200, headers: site.headers ?? {} });
  });
  return calls;
}

const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString().slice(0, 19);

/** A well-run domain: everything an A grade needs. */
export function goodDomain(domain: string): FakeNet {
  return {
    dns: {
      [domain]: {
        A: ["93.184.215.14"],
        MX: [`10 mx1.${domain}.`, `20 mx2.${domain}.`],
        TXT: ["v=spf1 include:_spf.mail.test -all", "some-other-verification=1"],
        ad: true,
      },
      "_spf.mail.test": { TXT: ["v=spf1 ip4:192.0.2.0/24 -all"] },
      [`_dmarc.${domain}`]: { TXT: [`v=DMARC1; p=reject; rua=mailto:dmarc@${domain}`] },
      [`selector1._domainkey.${domain}`]: { TXT: [`v=DKIM1; k=rsa; p=${"A".repeat(392)}`] },
    },
    sites: {
      [`https://${domain}/`]: {
        headers: {
          "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
          "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
          "x-content-type-options": "nosniff",
          "referrer-policy": "no-referrer",
          "permissions-policy": "camera=()",
        },
      },
      [`http://${domain}/`]: { status: 301, headers: { location: `https://${domain}/` } },
    },
    crtsh: [
      { issuer_name: "C=US, O=Let's Encrypt, CN=R11", name_value: `${domain}\nwww.${domain}`, not_before: inDays(-10), not_after: inDays(80) },
      { issuer_name: "C=US, O=Let's Encrypt, CN=R10", name_value: domain, not_before: inDays(-70), not_after: inDays(20) },
    ],
  };
}
