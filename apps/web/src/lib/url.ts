import { parseIPv4, parseIPv6 } from "@bluebench/shared";
import { sortFindings, type Finding } from "./findings";

/** decodeURIComponent that never throws; also turns + into a space as forms do. */
export function safeDecode(s: string, plusAsSpace = false): string {
  const input = plusAsSpace ? s.replace(/\+/g, " ") : s;
  try {
    return decodeURIComponent(input);
  } catch {
    // Decode valid %XX runs, leave broken ones as they are.
    return input.replace(/(?:%[0-9a-f]{2})+/gi, (run) => {
      try {
        return decodeURIComponent(run);
      } catch {
        return run;
      }
    });
  }
}

/** Repeatedly percent-decode (up to 5 layers) to unwrap double-encoding. Returns each layer. */
export function decodeLayers(input: string): string[] {
  const layers = [input];
  for (let i = 0; i < 5; i++) {
    const next = safeDecode(layers.at(-1)!);
    if (next === layers.at(-1)) break;
    layers.push(next);
  }
  return layers;
}

export interface UrlAnalysis {
  href: string;
  decoded: string;
  scheme: string;
  host: string;
  port: string;
  path: string;
  params: [string, string][];
  fragment: string;
  findings: Finding[];
}

export function analyzeUrl(href: string): UrlAnalysis | null {
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return null;
  }
  const findings: Finding[] = [];
  const host = url.hostname;
  const bareHost = host.replace(/^\[(.*)\]$/, "$1");
  const params = [...url.searchParams.entries()];

  if (url.username || url.password) {
    findings.push({
      severity: "critical",
      title: "Text before @ in the address",
      detail: `Everything before the @ is ignored. This link really goes to ${host}.`,
    });
  }
  if (parseIPv4(bareHost) !== null || parseIPv6(bareHost) !== null) {
    findings.push({ severity: "warning", title: "Links to a bare IP address", detail: "Legitimate sites rarely link without a domain name." });
  }
  if (host.split(".").some((l) => l.startsWith("xn--"))) {
    findings.push({
      severity: "warning",
      title: "Internationalised domain (xn--)",
      detail: "The name uses non-Latin characters, which can imitate a familiar domain.",
    });
  }
  for (const [key, value] of params) {
    const nested = /^(?:https?:)?\/\//i.test(value.trim()) ? value.trim() : null;
    if (nested) {
      findings.push({ severity: "warning", title: "Contains another URL", detail: `Parameter "${key}" points to ${nested}. This may be a redirect.` });
    }
  }
  if (url.port) findings.push({ severity: "info", title: "Non-standard port", detail: `Port ${url.port}.` });
  if (url.protocol === "http:") findings.push({ severity: "info", title: "Not encrypted", detail: "Uses http, not https." });
  if (host.split(".").length >= 5) {
    findings.push({ severity: "info", title: "Many subdomains", detail: "Long hostnames can hide the real domain at the end." });
  }

  return {
    href: url.href,
    decoded: safeDecode(url.href),
    scheme: url.protocol.replace(/:$/, ""),
    host,
    port: url.port,
    path: safeDecode(url.pathname),
    params,
    fragment: safeDecode(url.hash.replace(/^#/, "")),
    findings: sortFindings(findings),
  };
}
