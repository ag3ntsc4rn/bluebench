/**
 * Every URL the site serves. Used by the app to pick a page, and at build time to pre-render
 * each route to static HTML (with its own title, description and link-preview tags) and to
 * write sitemap.xml. Add a route here and it gets all of that.
 */

export const SITE_URL = "https://bluebench.dev";
export const SITE_NAME = "Bluebench";

export type ToolSlug = "ioc-lookup" | "jwt-decoder" | "email-header-analyzer" | "base64-decoder" | "url-decoder";

export interface ToolSection {
  heading: string;
  paragraphs: string[];
}

export interface ToolRoute {
  slug: ToolSlug;
  path: `/${ToolSlug}`;
  /** Short name for links and the footer. */
  name: string;
  /** <title> */
  title: string;
  /** <meta name="description">, ~150 characters. */
  description: string;
  h1: string;
  lead: string;
  /** Pasted into the box by "Try an example". Must be harmless and detected as this tool's kind. */
  example: string;
  /** Paste box hint for this tool. */
  placeholder: string;
  sections: ToolSection[];
}

const PRIVATE =
  "Decoding happens in your browser. What you paste isn't sent to our server or anyone else, so it's safe to use with tokens and emails from real incidents.";

export const TOOLS: readonly ToolRoute[] = [
  {
    slug: "ioc-lookup",
    path: "/ioc-lookup",
    name: "IOC lookup",
    title: "Free IOC lookup: check IPs, domains, URLs and file hashes | Bluebench",
    description:
      "Check an IP address, domain, URL or MD5/SHA-1/SHA-256 hash against URLhaus, ThreatFox, MalwareBazaar and Google Safe Browsing. Free, no sign-up, not logged.",
    h1: "IOC lookup",
    lead: "Check an IP address, domain, URL or file hash against public threat intelligence. Paste it defanged or not.",
    placeholder: "e.g. 203.0.113.7, example.com, a URL or a SHA-256 hash",
    example: "hxxps://example[.]com/login",
    sections: [
      {
        heading: "What it checks",
        paragraphs: [
          "Domains, URLs and IPv4 addresses are checked against abuse.ch's URLhaus and ThreatFox, and URLs and domains also against Google Safe Browsing. MD5, SHA-1 and SHA-256 hashes are checked against MalwareBazaar, ThreatFox and URLhaus.",
          "You get one merged verdict plus each source's answer, with links to the full entry. A clean result is shown as \"not listed\", never \"safe\": new threats take time to be reported.",
        ],
      },
      {
        heading: "Private by default",
        paragraphs: [
          "Detection and refanging run in your browser. The indicator is sent only when you press Check reputation, and it isn't logged. Cached results are stored under a one-way hash.",
        ],
      },
    ],
  },
  {
    slug: "jwt-decoder",
    path: "/jwt-decoder",
    name: "JWT decoder",
    title: "JWT decoder: decode and inspect JSON Web Tokens in your browser | Bluebench",
    description:
      "Decode a JWT's header and payload, see expiry and issue times in plain dates, and spot red flags like alg \"none\". Runs in your browser; tokens never leave it.",
    h1: "JWT decoder",
    lead: "Paste a JSON Web Token to see its header, claims and timestamps, with red flags called out.",
    placeholder: "Paste a token, e.g. eyJhbGciOi…",
    example:
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkV4YW1wbGUgVXNlciIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDAzNjAwfQ.c2lnbmF0dXJlLW5vdC12ZXJpZmllZA",
    sections: [
      {
        heading: "What it shows",
        paragraphs: [
          "The decoded header and payload as formatted JSON, with exp, iat and nbf turned into readable dates. It flags tokens that are expired, not valid yet, have no expiry, have no signature, or use alg \"none\".",
          "It doesn't verify the signature: that needs the issuer's key, and pasting secret keys into websites is a bad habit.",
        ],
      },
      { heading: "Your token stays with you", paragraphs: [PRIVATE] },
    ],
  },
  {
    slug: "email-header-analyzer",
    path: "/email-header-analyzer",
    name: "Email header analyzer",
    title: "Email header analyzer: SPF, DKIM, DMARC and hop path | Bluebench",
    description:
      "Paste raw email headers to see SPF, DKIM and DMARC results, the delivery path with delays, and plain-English phishing red flags. Runs in your browser.",
    h1: "Email header analyzer",
    lead: "Paste the full headers of a suspicious email to see who really sent it, how it travelled and what doesn't add up.",
    placeholder: "Paste the full headers, starting with Received: or Delivered-To:",
    example: [
      "Received: from mail.example.net (mail.example.net [192.0.2.10]) by mx.example.org with ESMTPS; Tue, 08 Oct 2024 10:00:05 +0000",
      "Received: from [198.51.100.7] by mail.example.net with ESMTP; Tue, 08 Oct 2024 10:00:01 +0000",
      "Authentication-Results: mx.example.org; spf=softfail smtp.mailfrom=example.net; dkim=none; dmarc=fail header.from=example.com",
      "From: \"Example Support\" <support@example.com>",
      "Reply-To: help-desk@example.net",
      "To: you@example.org",
      "Subject: Action required: verify your account",
      "Date: Tue, 08 Oct 2024 10:00:00 +0000",
    ].join("\n"),
    sections: [
      {
        heading: "What it checks",
        paragraphs: [
          "SPF, DKIM and DMARC results from Authentication-Results, and whether the signing and bounce domains line up with the From address. The Received hops in order, with the delay at each step.",
          "Red flags in plain English: replies going to a different address, a display name showing another address, failed or missing authentication, and hop times that go backwards.",
        ],
      },
      {
        heading: "How to get the headers",
        paragraphs: [
          "Gmail: open the message, then More (⋮) → Show original. Outlook: open the message, then File → Properties → Internet headers (desktop) or ⋯ → View → View message source (web). Apple Mail: View → Message → All Headers.",
        ],
      },
      { heading: "Headers stay on your device", paragraphs: [PRIVATE] },
    ],
  },
  {
    slug: "base64-decoder",
    path: "/base64-decoder",
    name: "Base64 decoder",
    title: "Base64 decoder with file-type detection | Bluebench",
    description:
      "Decode base64 and base64url to text or a hex dump, and recognise what's inside: executables, Office files, archives, PDFs and more. Runs in your browser.",
    h1: "Base64 decoder",
    lead: "Paste base64 (wrapped or not, standard or URL-safe) to see what it decodes to.",
    placeholder: "e.g. aGVsbG8gd29ybGQ=",
    example: "aHR0cHM6Ly9leGFtcGxlLmNvbS9sb2dpbj9uZXh0PS9hY2NvdW50",
    sections: [
      {
        heading: "What it shows",
        paragraphs: [
          "Decoded text when it's text, or a hex dump when it isn't. Known file signatures are named, so a blob that's really a Windows executable, Office document, ZIP, PDF or image says so.",
          "If the decoded text is itself something Bluebench understands, such as a URL or a JWT, you can analyse it with one tap.",
        ],
      },
      { heading: "Nothing is uploaded", paragraphs: [PRIVATE] },
    ],
  },
  {
    slug: "url-decoder",
    path: "/url-decoder",
    name: "URL decoder",
    title: "URL decoder and analyzer: decode and inspect suspicious links | Bluebench",
    description:
      "Decode percent-encoded URLs layer by layer, split out every query parameter, and spot tricks like text before @, bare IPs and punycode. Runs in your browser.",
    h1: "URL decoder",
    lead: "Paste a link or URL-encoded text to decode it fully and see how it's built.",
    placeholder: "e.g. https://example.com/?next=%2Flogin",
    example: "https://example.com/redirect?to=https%253A%252F%252Fexample.net%252Flogin%253Fuser%253Dyou",
    sections: [
      {
        heading: "What it shows",
        paragraphs: [
          "Every layer of percent-encoding peeled back, the scheme, host, port, path and fragment, and each query parameter decoded on its own line.",
          "Common link tricks are flagged: text before @ in the address, bare IP addresses, punycode (xn--) domains, lots of subdomains, non-standard ports, unencrypted http and URLs hidden inside other URLs.",
        ],
      },
      { heading: "Links aren't visited", paragraphs: ["Bluebench never opens the link. " + PRIVATE] },
    ],
  },
];

export interface PageMeta {
  path: string;
  title: string;
  description: string;
}

export const HOME: PageMeta = {
  path: "/",
  title: "Bluebench: free IOC lookup, JWT decoder and email header analyzer",
  description:
    "Free, open-source security toolkit for defenders. Check IPs, domains, URLs and hashes, decode JWTs and base64, analyze email headers. Nothing you paste is logged.",
};

export interface ContentPage extends PageMeta {
  name: string;
  h1: string;
  lead: string;
  sections: ToolSection[];
}

/** The Domains tab, at its own URL so it can be found and shared. */
export const DOMAINS: ContentPage = {
  path: "/domain-checker",
  name: "Domain checker",
  title: "Domain security checker: SPF, DMARC, DKIM, DNSSEC and HTTPS grade | Bluebench",
  description:
    "Free report card for a domain's email and web security: SPF, DMARC, DKIM, DNSSEC, HTTPS, HSTS, security headers and certificate expiry, each with a fix.",
  h1: "Domain security checker",
  lead: "Get a letter grade for a domain's email and web security, with a one-line fix for every problem.",
  sections: [
    {
      heading: "What it checks",
      paragraphs: [
        "Email: whether SPF, DMARC and DKIM stop others sending mail as you, including SPF's 10-lookup limit, the DMARC policy that actually applies, and weak DKIM keys. DNS: whether the domain is signed with DNSSEC.",
        "Web: whether the site loads over HTTPS and redirects plain HTTP, sends HSTS and the recommended security headers, and when its newest certificate in public Certificate Transparency logs expires.",
      ],
    },
    {
      heading: "How it works",
      paragraphs: [
        "Bluebench reads the domain's public DNS through Cloudflare's 1.1.1.1, requests the site's home page over HTTPS and plain HTTP (following at most 3 redirects, identifying itself as Bluebench), and looks up certificates on crt.sh. It never scans ports or crawls beyond the home page. Reports are cached for an hour.",
      ],
    },
  ],
};

export const PRIVACY: PageMeta = {
  path: "/privacy",
  title: "Privacy | Bluebench",
  description: "What Bluebench sends, stores and shares (very little), the one cookie it sets, and how to contact us.",
};

export const NOT_FOUND: PageMeta = {
  path: "/404",
  title: "Page not found | Bluebench",
  description: "This page doesn't exist.",
};

export type Page =
  | { kind: "home" }
  | { kind: "privacy" }
  | { kind: "domains" }
  | { kind: "tool"; tool: ToolRoute }
  | { kind: "notfound" };

export function pageForPath(path: string): Page {
  const p = path.replace(/\/+$/, "") || "/";
  if (p === "/") return { kind: "home" };
  if (p === PRIVACY.path) return { kind: "privacy" };
  if (p === DOMAINS.path) return { kind: "domains" };
  const tool = TOOLS.find((t) => t.path === p);
  return tool ? { kind: "tool", tool } : { kind: "notfound" };
}

export function metaFor(page: Page): PageMeta {
  switch (page.kind) {
    case "home":
      return HOME;
    case "privacy":
      return PRIVACY;
    case "domains":
      return DOMAINS;
    case "tool":
      return page.tool;
    case "notfound":
      return NOT_FOUND;
  }
}

export const pathOf = (page: Page): string => (page.kind === "notfound" ? NOT_FOUND.path : metaFor(page).path);
