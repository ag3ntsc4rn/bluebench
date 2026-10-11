import { normalizeDomain } from "./domain.ts";
import { base64ToBytes, bytesToText, tryParseJson } from "./encoding.ts";
import { formatIPv4, formatIPv6, parseIPv4, parseIPv6 } from "./ip.ts";

/** Maximum paste size, in characters. */
export const MAX_PASTE_LENGTH = 65536;

export type IndicatorKind =
  | "ipv4"
  | "ipv6"
  | "domain"
  | "url"
  | "md5"
  | "sha1"
  | "sha256"
  | "email"
  | "jwt"
  | "base64"
  | "url-encoded"
  | "email-headers";

export const KIND_LABELS: Readonly<Record<IndicatorKind, string>> = {
  ipv4: "IPv4 address",
  ipv6: "IPv6 address",
  domain: "Domain",
  url: "URL",
  md5: "MD5 hash",
  sha1: "SHA-1 hash",
  sha256: "SHA-256 hash",
  email: "Email address",
  jwt: "JWT",
  base64: "Base64",
  "url-encoded": "URL-encoded text",
  "email-headers": "Email headers",
};

export interface Detection {
  kind: IndicatorKind;
  /** Normalized value: refanged, trimmed, lowercased where case doesn't matter. */
  value: string;
  /** True if the input was defanged (hxxp, [.]) and we refanged it. */
  refanged: boolean;
}

/** Undo common defanging: hxxp(s), [.], (.), {.}, [dot], [:], [@], [at]. */
export function refang(input: string): string {
  return input
    .replace(/\bhxxp(s?)(?=(?:\[:\]|:)\/\/)/gi, "http$1")
    .replace(/\bfxp(?=(?:\[:\]|:)\/\/)/gi, "ftp")
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[@\]|\[at\]|\(at\)/gi, "@");
}

const KNOWN_HEADERS = new Set([
  "received", "from", "to", "subject", "date", "message-id", "return-path", "reply-to",
  "authentication-results", "dkim-signature", "received-spf", "mime-version", "delivered-to",
  "arc-authentication-results", "x-mailer", "content-type",
]);

/** Raw email headers: several `Name: value` lines, mostly ones we recognise. */
export function looksLikeEmailHeaders(text: string): boolean {
  const lines = text.split(/\r?\n/);
  if (lines.length < 3) return false;
  let fields = 0;
  let known = 0;
  for (const line of lines) {
    if (line.trim() === "") {
      if (fields > 0) break; // end of header block
      continue;
    }
    if (/^[ \t]/.test(line)) continue; // folded continuation
    const m = /^([A-Za-z0-9-]+):/.exec(line);
    if (!m) continue;
    fields++;
    if (KNOWN_HEADERS.has(m[1]!.toLowerCase())) known++;
  }
  return fields >= 3 && known >= 2;
}

const BASE64URL_SEGMENT = /^[A-Za-z0-9_-]+$/;

function isJwt(s: string): boolean {
  const parts = s.split(".");
  if (parts.length !== 3) return false;
  const [header, payload, sig] = parts as [string, string, string];
  if (!BASE64URL_SEGMENT.test(header) || !BASE64URL_SEGMENT.test(payload)) return false;
  if (sig !== "" && !BASE64URL_SEGMENT.test(sig)) return false;
  const bytes = base64ToBytes(header);
  const json = bytes && tryParseJson(new TextDecoder().decode(bytes));
  return typeof json === "object" && json !== null && "alg" in json;
}

/** Magic bytes worth recognising in a decoded base64 blob. */
export function sniffFileType(bytes: Uint8Array): string | null {
  const starts = (...sig: number[]) => sig.every((b, i) => bytes[i] === b);
  if (starts(0x4d, 0x5a)) return "Windows executable (PE)";
  if (starts(0x7f, 0x45, 0x4c, 0x46)) return "Linux executable (ELF)";
  if (starts(0x25, 0x50, 0x44, 0x46)) return "PDF document";
  if (starts(0x50, 0x4b, 0x03, 0x04)) return "ZIP archive (or Office document)";
  if (starts(0xd0, 0xcf, 0x11, 0xe0)) return "Legacy Office document (OLE)";
  if (starts(0x1f, 0x8b)) return "gzip archive";
  if (starts(0x52, 0x61, 0x72, 0x21)) return "RAR archive";
  if (starts(0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c)) return "7-Zip archive";
  if (starts(0x89, 0x50, 0x4e, 0x47)) return "PNG image";
  if (starts(0xff, 0xd8, 0xff)) return "JPEG image";
  if (starts(0x47, 0x49, 0x46, 0x38)) return "GIF image";
  if (starts(0x7b, 0x5c, 0x72, 0x74, 0x66)) return "RTF document";
  if (starts(0xca, 0xfe, 0xba, 0xbe)) return "Java class / Mach-O";
  return null;
}

function isBase64(s: string): boolean {
  if (s.length < 8 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(s)) return false;
  if (/[+/]/.test(s) && /[-_]/.test(s)) return false; // mixed alphabets
  if (/^[a-z]+$/i.test(s) || /^[0-9a-f]+$/i.test(s)) return false; // plain words, numbers, hex
  const bytes = base64ToBytes(s);
  if (!bytes || bytes.length === 0) return false;
  return bytesToText(bytes) !== null || sniffFileType(bytes) !== null || s.length >= 64;
}

function detectUrl(s: string): string | null {
  let candidate = s;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    // Bare host followed by a path, query or port, e.g. example.com/login
    const m = /^([^/?#:@\s]+)(?::\d{1,5})?[/?#]/.exec(s);
    if (!m || (!normalizeDomain(m[1]!) && parseIPv4(m[1]!) === null)) return null;
    candidate = `http://${s}`;
  } else if (!/^(?:https?|ftp):\/\//i.test(s)) {
    return null;
  }
  try {
    const url = new URL(candidate);
    if (!url.hostname) return null;
    return url.href;
  } catch {
    return null;
  }
}

/**
 * Detect what a pasted string is. Returns candidates, most likely first; empty if unrecognised.
 * Pure and synchronous; nothing leaves the caller.
 */
export function detect(input: string): Detection[] {
  if (input.length > MAX_PASTE_LENGTH) return [];
  const trimmed = input.trim();
  if (!trimmed) return [];

  if (/\n/.test(trimmed)) {
    if (looksLikeEmailHeaders(trimmed)) return [{ kind: "email-headers", value: trimmed, refanged: false }];
    // Base64 is often wrapped at 64 or 76 columns.
    const joined = trimmed.replace(/\s+/g, "");
    return isBase64(joined) ? [{ kind: "base64", value: joined, refanged: false }] : [];
  }

  const value = refang(trimmed);
  const refanged = value !== trimmed;
  const out: Detection[] = [];
  const add = (kind: IndicatorKind, v: string) => out.push({ kind, value: v, refanged });

  if (isJwt(value)) add("jwt", value);

  if (/^[0-9a-f]{32}$/i.test(value)) add("md5", value.toLowerCase());
  else if (/^[0-9a-f]{40}$/i.test(value)) add("sha1", value.toLowerCase());
  else if (/^[0-9a-f]{64}$/i.test(value)) add("sha256", value.toLowerCase());

  const v4 = parseIPv4(value);
  if (v4 !== null) add("ipv4", formatIPv4(v4));
  const v6 = parseIPv6(value.replace(/^\[(.*)\]$/, "$1"));
  if (v6 !== null) add("ipv6", formatIPv6(v6));

  const email = /^([^\s@<>"]+)@([^\s@<>"]+)$/.exec(value);
  const emailDomain = email && normalizeDomain(email[2]!);
  if (email && emailDomain) add("email", `${email[1]}@${emailDomain}`);

  const url = detectUrl(value);
  if (url) add("url", url);

  if (out.length === 0) {
    const domain = normalizeDomain(value);
    if (domain) add("domain", domain);
  }

  if (/%[0-9a-f]{2}/i.test(value) && !out.some((d) => d.kind === "url")) add("url-encoded", trimmed);
  if (out.length === 0 && isBase64(trimmed)) add("base64", trimmed);

  return out;
}
