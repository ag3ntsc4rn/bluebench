import { VERIFY_PREFIX } from "@bluebench/shared";
import { DNS_TYPES, joinTxt, type Resolver } from "../dns.ts";

export const verifyRecord = (token: string) => `${VERIFY_PREFIX}${token}`;

export function newVerifyToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Is `bluebench-verify=<token>` published as a TXT record at the domain itself?
 * Resolves false for NXDOMAIN or no match; throws on SERVFAIL or a network error, so callers can tell
 * "removed" from "couldn't ask" (a resolver hiccup mustn't pause someone's monitoring).
 */
export async function hasVerifyRecord(r: Resolver, domain: string, token: string): Promise<boolean> {
  const a = await r.query(domain, "TXT");
  if (a.status !== 0 && a.status !== 3) throw new Error(`DNS status ${a.status}`);
  const want = verifyRecord(token);
  return a.records.some((rec) => rec.type === DNS_TYPES.TXT && joinTxt(rec.data).trim() === want);
}
