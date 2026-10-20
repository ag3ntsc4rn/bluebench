import { decodeEncodedWords } from "./email-headers";

/**
 * A small MIME parser for the phishing triage tool: enough of RFC 2045–2047 and 2231 to find a message's
 * headers, text and HTML bodies and attachments. Runs in the browser; no dependency. It never throws:
 * malformed input gives a best-effort result plus warnings.
 */

/** Largest .eml file the triage tool reads. */
export const MAX_EML_BYTES = 10 * 1024 * 1024;
/** Deepest nesting of multiparts we follow. */
export const MAX_MIME_DEPTH = 10;
/** Most parts we look at in one message. */
export const MAX_MIME_PARTS = 200;

export interface MimeAttachment {
  filename: string;
  contentType: string;
  size: number;
  bytes: Uint8Array<ArrayBuffer>;
}

export interface ParsedMessage {
  /** The top-level header block, as text. Empty if the input didn't start with headers. */
  headers: string;
  /** Decoded text/plain bodies, in order. */
  text: string[];
  /** Decoded text/html bodies, in order. Never rendered: only parsed. */
  html: string[];
  attachments: MimeAttachment[];
  /** Plain-English notes about anything we had to skip or guess. */
  warnings: string[];
}

interface Header {
  name: string;
  value: string;
}

/** A header value split into its main value and parameters (RFC 2045 + RFC 2231). */
export interface ParsedHeaderValue {
  value: string;
  params: Record<string, string>;
}

// --- Bytes and "binary strings" (one char per byte, 0–255) ---

function bytesToBinary(bytes: Uint8Array): string {
  let out = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) out += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  return out;
}

function binaryToBytes(bin: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
  return out;
}

/** Decode with the named charset, falling back to UTF-8 for unknown or missing labels. */
export function decodeCharset(bytes: Uint8Array, charset?: string): string {
  try {
    return new TextDecoder(charset?.trim() || "utf-8").decode(bytes);
  } catch {
    return new TextDecoder("utf-8").decode(bytes);
  }
}

const B64 = (() => {
  const t = new Int16Array(256).fill(-1);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (let i = 0; i < alphabet.length; i++) t[alphabet.charCodeAt(i)] = i;
  t["-".charCodeAt(0)] = 62; // tolerate base64url
  t["_".charCodeAt(0)] = 63;
  return t;
})();

/** Lenient base64: skips anything outside the alphabet and stops at padding. Never throws. */
export function decodeBase64(bin: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(Math.floor((bin.length * 3) / 4) + 3);
  let n = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < bin.length; i++) {
    const c = bin.charCodeAt(i);
    if (c === 61) break; // "="
    const v = c < 256 ? B64[c]! : -1;
    if (v < 0) continue;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[n++] = (acc >> bits) & 0xff;
    }
  }
  return out.slice(0, n);
}

/** Quoted-printable to bytes (as a binary string). Soft line breaks are removed; bad escapes are kept as-is. */
export function decodeQuotedPrintable(bin: string): string {
  return bin
    .replace(/[ \t]+(?=\r?\n)/g, "") // trailing whitespace is padding
    .replace(/=\r?\n/g, "")
    .replace(/=([0-9A-Fa-f]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
}

// --- Headers ---

/** Split a message (or part) into its header block and body. Accepts CRLF or LF. */
export function splitHeaderBody(bin: string): { head: string; body: string } {
  const m = /\r?\n\r?\n/.exec(bin);
  if (!m) return { head: bin, body: "" };
  return { head: bin.slice(0, m.index), body: bin.slice(m.index + m[0].length) };
}

/** Does this text start with a header field? (So a pasted body without headers isn't misread.) */
function startsWithHeader(bin: string): boolean {
  return /^[!-9;-~]+:/.test(bin.replace(/^\s+/, ""));
}

function parseHeaders(head: string): Header[] {
  const out: Header[] = [];
  for (const line of head.split(/\r?\n/)) {
    if (/^[ \t]/.test(line)) {
      const last = out.at(-1);
      if (last) last.value += ` ${line.trim()}`;
      continue;
    }
    const m = /^([!-9;-~]+):[ \t]*(.*)$/.exec(line);
    if (m) out.push({ name: m[1]!.toLowerCase(), value: m[2]!.trim() });
  }
  return out;
}

/** Split on `;` outside quoted strings. */
function splitParams(value: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < value.length; i++) {
    const c = value[i]!;
    if (quoted && c === "\\" && i + 1 < value.length) {
      cur += c + value[++i];
      continue;
    }
    if (c === '"') quoted = !quoted;
    if (c === ";" && !quoted) {
      out.push(cur);
      cur = "";
    } else cur += c;
  }
  out.push(cur);
  return out;
}

const unquote = (v: string) => {
  const t = v.trim();
  return t.length >= 2 && t.startsWith('"') && t.endsWith('"') ? t.slice(1, -1).replace(/\\(.)/g, "$1") : t;
};

function percentDecode(text: string, charset: string): string {
  const bin = text.replace(/%([0-9A-Fa-f]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
  // Unencoded characters in an extended value may be non-ASCII already (sloppy senders): keep them.
  if (/[^\x00-\xff]/.test(bin)) return bin;
  return decodeCharset(binaryToBytes(bin), charset);
}

/** Parse `type/subtype; a=b; c="d"`, including RFC 2231 continuations (name*0*=…) and charsets (name*=utf-8''…). */
export function parseHeaderValue(raw: string): ParsedHeaderValue {
  const [first = "", ...rest] = splitParams(raw);
  const params: Record<string, string> = {};
  const sections = new Map<string, { index: number; extended: boolean; value: string }[]>();
  for (const p of rest) {
    const eq = p.indexOf("=");
    if (eq < 0) continue;
    const key = p.slice(0, eq).trim().toLowerCase();
    const value = p.slice(eq + 1);
    const m = /^(.+?)(?:\*(\d+))?(\*)?$/.exec(key);
    if (!m) continue;
    const [, name, index, star] = m;
    if (index === undefined && !star) {
      if (!(name! in params)) params[name!] = unquote(value);
      continue;
    }
    const list = sections.get(name!) ?? [];
    list.push({ index: index === undefined ? 0 : Number(index), extended: Boolean(star), value: unquote(value) });
    sections.set(name!, list);
  }
  for (const [name, list] of sections) {
    list.sort((a, b) => a.index - b.index);
    let charset = "utf-8";
    let out = "";
    list.forEach((s, i) => {
      let v = s.value;
      if (s.extended && i === 0) {
        const m = /^([^']*)'[^']*'(.*)$/s.exec(v);
        if (m) {
          charset = m[1] || "utf-8";
          v = m[2]!;
        }
      }
      out += s.extended ? percentDecode(v, charset) : v;
    });
    params[name] = out; // RFC 2231 values win over plain ones
  }
  return { value: first.trim().toLowerCase(), params };
}

// --- Parts ---

interface Ctx {
  parts: number;
  /** The input was a paste (Unicode text, held here as UTF-8) rather than the raw bytes of a file. */
  unicode: boolean;
  out: ParsedMessage;
  warned: Set<string>;
}

function warn(ctx: Ctx, message: string) {
  if (ctx.warned.has(message)) return;
  ctx.warned.add(message);
  ctx.out.warnings.push(message);
}

/** Split a multipart body on its boundary. Returns null if no delimiter line was found. */
function splitMultipart(body: string, boundary: string, ctx: Ctx): string[] | null {
  const delim = `--${boundary}`;
  const parts: string[] = [];
  let start = -1;
  let found = false;
  let closed = false;
  let pos = 0;
  while (pos < body.length) {
    let eol = body.indexOf("\n", pos);
    if (eol < 0) eol = body.length;
    if (body.startsWith(delim, pos)) {
      const rest = body.slice(pos + delim.length, eol).replace(/\r$/, "");
      const closing = rest.startsWith("--");
      if (closing || rest.trim() === "") {
        found = true;
        if (start >= 0) {
          // The line break before a delimiter belongs to the delimiter.
          let end = pos;
          if (body[end - 1] === "\n") end--;
          if (body[end - 1] === "\r") end--;
          parts.push(body.slice(start, Math.max(start, end)));
        }
        if (closing) {
          closed = true;
          start = -1;
          break;
        }
        start = eol + 1;
      }
    }
    pos = eol + 1;
  }
  if (!found) return null;
  if (start >= 0 && start <= body.length) parts.push(body.slice(start));
  if (!closed) warn(ctx, "A multipart section has no closing boundary: the message may be cut short.");
  return parts;
}

function header(headers: Header[], name: string): string | undefined {
  return headers.find((h) => h.name === name)?.value;
}

function decodeTransfer(body: string, encoding: string): { bin: string; encoded: boolean } {
  if (encoding === "base64") return { bin: bytesToBinary(decodeBase64(body)), encoded: true };
  if (encoding === "quoted-printable") return { bin: decodeQuotedPrintable(body), encoded: true };
  return { bin: body, encoded: false };
}

function walk(bin: string, ctx: Ctx, depth: number, defaultType: string, top: boolean) {
  if (ctx.parts >= MAX_MIME_PARTS) {
    warn(ctx, `Stopped after ${MAX_MIME_PARTS} parts. The rest of the message wasn't analysed.`);
    return;
  }
  ctx.parts++;

  let headers: Header[] = [];
  let body = bin;
  if (top) {
    if (startsWithHeader(bin)) {
      const split = splitHeaderBody(bin.replace(/^(?:\r?\n)+/, ""));
      ctx.out.headers = decodeCharset(binaryToBytes(split.head), "utf-8");
      headers = parseHeaders(ctx.out.headers);
      body = split.body;
    }
  } else {
    // A part may start straight with a blank line: no headers, defaults apply.
    if (/^\r?\n/.test(bin)) body = bin.replace(/^\r?\n/, "");
    else {
      const split = splitHeaderBody(bin);
      headers = parseHeaders(decodeCharset(binaryToBytes(split.head), "utf-8"));
      body = split.body;
    }
  }

  const ct = parseHeaderValue(header(headers, "content-type") ?? defaultType);
  const type = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(ct.value) ? ct.value : "text/plain";
  const encoding = (header(headers, "content-transfer-encoding") ?? "7bit").trim().toLowerCase();
  const disposition = parseHeaderValue(header(headers, "content-disposition") ?? "");

  if (type.startsWith("multipart/")) {
    const boundary = ct.params.boundary;
    if (depth >= MAX_MIME_DEPTH) {
      warn(ctx, `Parts nested more than ${MAX_MIME_DEPTH} deep weren't analysed.`);
      return;
    }
    const parts = boundary ? splitMultipart(body, boundary, ctx) : null;
    if (!parts) {
      warn(ctx, "A multipart section has a missing or wrong boundary, so it's shown as plain text.");
      leaf(body, "text/plain", ct.params.charset, "7bit", "", "", ctx);
      return;
    }
    const childDefault = type === "multipart/digest" ? "message/rfc822" : "text/plain";
    for (const p of parts) walk(p, ctx, depth + 1, childDefault, false);
    return;
  }

  const rawName = disposition.params.filename ?? ct.params.name ?? "";
  leaf(body, type, ct.params.charset, encoding, disposition.value, rawName, ctx);
}

function leaf(body: string, type: string, charset: string | undefined, encoding: string, disposition: string, rawName: string, ctx: Ctx) {
  const filename = decodeEncodedWords(rawName).replace(/[\r\n]/g, "").trim();
  const isBody = (type === "text/plain" || type === "text/html") && disposition !== "attachment" && !filename;
  const { bin, encoded } = decodeTransfer(body, encoding);
  const bytes = binaryToBytes(bin);

  if (isBody) {
    // A paste was already text (we hold it as UTF-8), so only base64/quoted-printable output uses the declared charset.
    const text = decodeCharset(bytes, ctx.unicode && !encoded ? "utf-8" : charset);
    (type === "text/html" ? ctx.out.html : ctx.out.text).push(text);
    return;
  }

  const fallback = type === "message/rfc822" ? "attached-message.eml" : "(no name)";
  ctx.out.attachments.push({ filename: filename || fallback, contentType: type, size: bytes.length, bytes });
}

/**
 * Parse a raw message: a pasted string (already Unicode) or the bytes of an .eml file. Never throws.
 */
export function parseMime(input: string | Uint8Array): ParsedMessage {
  const out: ParsedMessage = { headers: "", text: [], html: [], attachments: [], warnings: [] };
  const unicode = typeof input === "string";
  const ctx: Ctx = { parts: 0, unicode, out, warned: new Set() };
  try {
    // Work on bytes, one char per byte. A paste becomes UTF-8 first.
    walk(bytesToBinary(unicode ? new TextEncoder().encode(input) : input), ctx, 0, "text/plain", true);
  } catch {
    warn(ctx, "Part of this message couldn't be read.");
  }
  return out;
}

/** True when the text is a whole message: a header block followed by a non-empty body. */
export function looksLikeFullMessage(text: string): boolean {
  const trimmed = text.replace(/^\s+/, "");
  if (!startsWithHeader(trimmed)) return false;
  const { body } = splitHeaderBody(trimmed);
  return body.trim().length > 0;
}
