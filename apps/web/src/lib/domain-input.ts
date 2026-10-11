import { canonicalDomain, detect } from "@bluebench/shared";

/** Accept a domain, a URL or an email address (defanged or not) and return the domain to check. */
export function domainFromInput(input: string): string | null {
  for (const d of detect(input)) {
    if (d.kind === "domain") return canonicalDomain(d.value);
    if (d.kind === "email") return canonicalDomain(d.value.slice(d.value.lastIndexOf("@") + 1));
    if (d.kind === "url") {
      try {
        return canonicalDomain(new URL(d.value).hostname);
      } catch {
        return null;
      }
    }
  }
  return null;
}
