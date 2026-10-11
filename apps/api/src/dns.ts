/**
 * Per-report outbound request budget. The free plan allows ~50 subrequests per incoming request;
 * a domain report spends them on DNS queries, fetches of the site and crt.sh. Checks that can't get
 * budget report themselves as skipped instead of failing the whole report.
 */
export class Budget {
  used = 0;
  constructor(readonly max: number) {}
  /** Reserve one subrequest; false if the budget is spent. */
  take(): boolean {
    if (this.used >= this.max) return false;
    this.used++;
    return true;
  }
}

export class BudgetExceeded extends Error {
  constructor() {
    super("Out of request budget for this report");
  }
}

export const DNS_TYPES = { A: 1, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, DS: 43 } as const;
export type DnsType = keyof typeof DNS_TYPES;

export interface DnsAnswer {
  /** DNS RCODE: 0 = NOERROR, 2 = SERVFAIL (e.g. broken DNSSEC), 3 = NXDOMAIN. */
  status: number;
  /** Authenticated Data: the resolver validated DNSSEC for this answer. */
  ad: boolean;
  records: { type: number; data: string }[];
}

const DOH_URL = "https://cloudflare-dns.com/dns-query";
const DNS_TIMEOUT_MS = 4000;

/** TXT data arrives as one or more quoted strings ("v=spf1 " "include:…"); join them. */
export function joinTxt(data: string): string {
  const parts = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]!.replace(/\\(.)/g, "$1"));
  return parts.length > 0 ? parts.join("") : data;
}

/** DNS-over-HTTPS (Cloudflare 1.1.1.1) with per-report memoisation and budget. */
export class Resolver {
  private memo = new Map<string, Promise<DnsAnswer>>();

  constructor(private budget: Budget) {}

  query(name: string, type: DnsType): Promise<DnsAnswer> {
    const key = `${type} ${name.toLowerCase()}`;
    let p = this.memo.get(key);
    if (!p) {
      p = this.fetch(name, type);
      this.memo.set(key, p);
    }
    return p;
  }

  private async fetch(name: string, type: DnsType): Promise<DnsAnswer> {
    if (!this.budget.take()) throw new BudgetExceeded();
    const res = await fetch(`${DOH_URL}?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(DNS_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`DNS HTTP ${res.status}`);
    const data = (await res.json()) as { Status?: number; AD?: boolean; Answer?: { type: number; data: string }[] };
    return { status: data.Status ?? 2, ad: data.AD === true, records: data.Answer ?? [] };
  }

  /** TXT strings at a name (CNAMEs followed by the resolver). Empty for NXDOMAIN/NODATA. */
  async txt(name: string): Promise<string[]> {
    const a = await this.query(name, "TXT");
    return a.records.filter((r) => r.type === DNS_TYPES.TXT).map((r) => joinTxt(r.data));
  }

  /** A and AAAA addresses for a host; shaped for safeFetch's resolver hook. */
  async addresses(host: string): Promise<string[]> {
    const [a, aaaa] = await Promise.all([this.query(host, "A"), this.query(host, "AAAA")]);
    return [...a.records, ...aaaa.records].filter((r) => r.type === DNS_TYPES.A || r.type === DNS_TYPES.AAAA).map((r) => r.data);
  }
}
