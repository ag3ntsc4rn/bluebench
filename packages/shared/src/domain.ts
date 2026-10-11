const LABEL = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?$/;
const TLD = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;

/**
 * Normalize a hostname to lowercase ASCII (punycode), without a trailing dot.
 * Returns null if it isn't a plausible public DNS name (needs at least two labels and an alphabetic TLD).
 */
export function normalizeDomain(input: string): string | null {
  let host = input.trim().toLowerCase().replace(/\.$/, "");
  if (!host || host.length > 253) return null;
  if (/[^\x00-\x7f]/.test(host)) {
    // Internationalized name: let the URL parser apply IDNA/punycode.
    if (/[\s/?#@:[\]\\%]/.test(host)) return null;
    try {
      host = new URL(`http://${host}`).hostname;
    } catch {
      return null;
    }
  }
  const labels = host.split(".");
  if (labels.length < 2) return null;
  if (!TLD.test(labels.at(-1)!)) return null;
  return labels.every((l) => LABEL.test(l)) ? host : null;
}

// Common multi-label public suffixes. A heuristic, not the full Public Suffix List.
const MULTI_LABEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.nz", "org.nz", "net.nz", "govt.nz",
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
  "co.in", "net.in", "org.in", "gov.in", "ac.in",
  "co.za", "org.za", "gov.za",
  "com.br", "net.br", "org.br", "gov.br",
  "com.cn", "net.cn", "org.cn", "gov.cn",
  "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw", "com.my", "com.ph",
  "co.kr", "or.kr", "co.il", "org.il", "co.id", "or.id", "co.th", "in.th",
]);

/** Approximate organizational domain (eTLD+1), used for DMARC-style alignment checks. */
export function orgDomain(domain: string): string {
  const labels = domain.toLowerCase().replace(/\.$/, "").split(".");
  const take = labels.length >= 3 && MULTI_LABEL_SUFFIXES.has(labels.slice(-2).join(".")) ? 3 : 2;
  return labels.slice(-take).join(".");
}
