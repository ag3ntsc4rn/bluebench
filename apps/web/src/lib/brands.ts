import { orgDomain } from "@bluebench/shared";

/**
 * Brand impersonation heuristics for the header analyzer: a display name that names a well-known
 * brand while the address is on another domain, and sender domains that spell a brand with
 * look-alike characters (micros0ft, paypa1, rnicrosoft).
 *
 * Deliberately a short, curated list of the brands phishing kits imitate most. It is a heuristic:
 * a miss proves nothing, and a hit means "check this", which is how the findings are worded.
 */

export interface Brand {
  name: string;
  /** Matched as whole words in the display name, after look-alike characters are normalised. */
  keywords: readonly string[];
  /**
   * Domains the brand really sends from. A sender matches if its domain is one of these or a
   * subdomain of one. Free mail services (gmail.com, icloud.com) are left out on purpose:
   * "Google Security <x@gmail.com>" is exactly what we want to flag.
   */
  domains: readonly string[];
}

export const BRANDS: readonly Brand[] = [
  {
    name: "Microsoft",
    keywords: ["microsoft", "office 365", "office365", "microsoft 365", "onedrive", "sharepoint"],
    domains: ["microsoft.com", "microsoftonline.com", "office.com", "office365.com", "outlook.com", "live.com", "sharepointonline.com", "microsoft"],
  },
  { name: "Google", keywords: ["google", "gmail"], domains: ["google.com", "youtube.com", "google"] },
  { name: "Apple", keywords: ["apple", "icloud", "itunes", "app store"], domains: ["apple.com", "apple"] },
  {
    name: "Amazon",
    keywords: ["amazon", "aws", "prime video"],
    domains: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazon.ca", "amazon.com.au", "amazon.co.jp", "amazon.in", "amazonaws.com", "aws.com", "amazon"],
  },
  { name: "PayPal", keywords: ["paypal"], domains: ["paypal.com", "paypal.co.uk", "paypal.de", "paypal.fr", "paypal.it", "paypal.es", "paypal.com.au"] },
  { name: "DocuSign", keywords: ["docusign"], domains: ["docusign.com", "docusign.net"] },
  { name: "Adobe", keywords: ["adobe", "adobe sign"], domains: ["adobe.com", "adobesign.com", "echosign.com"] },
  { name: "Dropbox", keywords: ["dropbox"], domains: ["dropbox.com", "dropboxmail.com"] },
  { name: "DHL", keywords: ["dhl"], domains: ["dhl.com", "dhl.de", "dhl.co.uk", "dhl.fr", "dhl.nl"] },
  { name: "FedEx", keywords: ["fedex"], domains: ["fedex.com"] },
  { name: "UPS", keywords: ["ups"], domains: ["ups.com"] },
  { name: "USPS", keywords: ["usps"], domains: ["usps.com", "usps.gov"] },
  { name: "Royal Mail", keywords: ["royal mail", "royalmail"], domains: ["royalmail.com", "royalmail.co.uk"] },
  { name: "LinkedIn", keywords: ["linkedin"], domains: ["linkedin.com"] },
  {
    name: "Meta",
    keywords: ["facebook", "instagram", "whatsapp"],
    domains: ["facebook.com", "facebookmail.com", "instagram.com", "whatsapp.com", "meta.com"],
  },
  { name: "Netflix", keywords: ["netflix"], domains: ["netflix.com"] },
  { name: "Zoom", keywords: ["zoom"], domains: ["zoom.us", "zoom.com"] },
  { name: "Okta", keywords: ["okta"], domains: ["okta.com", "okta-emea.com"] },
  { name: "Slack", keywords: ["slack"], domains: ["slack.com"] },
  { name: "Coinbase", keywords: ["coinbase"], domains: ["coinbase.com"] },
  { name: "Binance", keywords: ["binance"], domains: ["binance.com"] },
  { name: "Intuit", keywords: ["intuit", "quickbooks", "turbotax"], domains: ["intuit.com"] },
  { name: "Wells Fargo", keywords: ["wells fargo", "wellsfargo"], domains: ["wellsfargo.com"] },
  { name: "Bank of America", keywords: ["bank of america", "bankofamerica"], domains: ["bankofamerica.com", "bofa.com"] },
  { name: "HMRC", keywords: ["hmrc"], domains: ["hmrc.gov.uk", "gov.uk"] },
  { name: "IRS", keywords: ["irs"], domains: ["irs.gov"] },
];

/** Cyrillic and Greek letters drawn like Latin ones. */
const CONFUSABLES: Readonly<Record<string, string>> = {
  а: "a", с: "c", е: "e", і: "i", о: "o", р: "p", х: "x", у: "y", ѕ: "s", ј: "j", ԁ: "d", һ: "h", ӏ: "l",
  ο: "o", α: "a", ν: "v", ρ: "p", τ: "t", ι: "i", κ: "k",
};

/**
 * Spellings of `s` with look-alike characters undone. "1" can stand for l or i, so there are two:
 * one reading 1 as l (paypa1), one as i (l1nkedin).
 */
export function skeletons(s: string): string[] {
  const base = [...s.normalize("NFKC").toLowerCase()]
    .map((c) => CONFUSABLES[c] ?? c)
    .join("")
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/0/g, "o");
  const asL = base.replace(/1/g, "l").replace(/\|/g, "l");
  const asI = base.replace(/1/g, "i").replace(/\|/g, "i");
  return asL === asI ? [asL] : [asL, asI];
}

/** True if `domain` is one of `domains` or a subdomain of one. */
function onDomain(domain: string, domains: readonly string[]): boolean {
  const d = domain.toLowerCase().replace(/\.$/, "");
  return domains.some((b) => d === b || d.endsWith(`.${b}`));
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function mentions(text: string, keyword: string): boolean {
  // Letters and digits on either side mean it's part of another word ("groups", "Chaseley").
  const re = new RegExp(`(?:^|[^a-z0-9])${escapeRe(keyword).replace(/ /g, "[\\s._-]*")}(?:$|[^a-z0-9])`);
  return re.test(text);
}

/** The brand a display name claims to be, if it names one (look-alike characters included). */
export function brandInDisplayName(display: string): Brand | null {
  if (!display.trim()) return null;
  const forms = [display.toLowerCase(), ...skeletons(display)];
  return BRANDS.find((b) => b.keywords.some((k) => forms.some((f) => mentions(f, k)))) ?? null;
}

export interface DomainImitation {
  brand: Brand;
  /** The domain uses look-alike characters (micros0ft) rather than just containing the name (microsoft-support). */
  lookalikeChars: boolean;
}

/**
 * Whether a sender domain imitates a brand it doesn't belong to: the brand's name spelt with
 * look-alike characters anywhere in the registrable name (micros0ft-support.com, paypa1.com),
 * or spelt correctly as a separate hyphenated part (microsoft-support.com, secure-paypal.net).
 * A name merely containing the letters (applebees.com) doesn't count.
 */
export function brandInDomain(domain: string): DomainImitation | null {
  const org = orgDomain(domain.toLowerCase());
  const label = org.slice(0, org.indexOf(".") < 0 ? undefined : org.indexOf("."));
  if (!label) return null;
  const forms = skeletons(label);
  for (const brand of BRANDS) {
    if (onDomain(domain, brand.domains)) continue;
    const names = [...new Set(brand.keywords.map((k) => k.replace(/ /g, "")))].filter((k) => k.length >= 4);
    for (const name of names) {
      if (forms.some((f) => f !== label && f.includes(name))) return { brand, lookalikeChars: true };
      if (label.split("-").includes(name) && label.includes("-")) return { brand, lookalikeChars: false };
    }
  }
  return null;
}

/** Whether the domain belongs to the brand (used to decide that "Microsoft" from microsoft.com is fine). */
export function isBrandDomain(brand: Brand, domain: string): boolean {
  return onDomain(domain, brand.domains);
}

/**
 * A 0 or 1 sitting between letters in the registrable name (examp1e, g0ogle): a common way to
 * imitate a name we don't list. Names like 1password or web3 don't match.
 */
export function hasLookalikeDigits(domain: string): boolean {
  const org = orgDomain(domain.toLowerCase());
  const label = org.slice(0, org.indexOf(".") < 0 ? undefined : org.indexOf("."));
  return /[a-z][01]+[a-z]/.test(label);
}
