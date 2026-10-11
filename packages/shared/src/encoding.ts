/** Decode standard or URL-safe base64 (padding optional). Returns null if the input isn't valid base64. */
export function base64ToBytes(input: string): Uint8Array | null {
  const s = input.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 === 1) return null;
  const unpadded = s.replace(/=+$/, "");
  if (s.length !== unpadded.length && s.length % 4 !== 0) return null;
  try {
    const bin = atob(unpadded + "=".repeat((4 - (unpadded.length % 4)) % 4));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

/** True if the string is mostly printable text: no NULs, at most 5 % control characters. */
export function isPrintableText(text: string): boolean {
  if (text.length === 0 || text.includes("\u0000")) return false;
  let control = 0;
  for (const ch of text) {
    const c = ch.codePointAt(0)!;
    if ((c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) || (c >= 0x7f && c < 0xa0) || c === 0xfffd) control++;
  }
  return control / text.length <= 0.05;
}

export type TextEncodingName = "UTF-8" | "UTF-16LE";

/**
 * Decode bytes as text if they look like text. Tries UTF-16LE first when every other byte is zero
 * (PowerShell `-EncodedCommand` payloads), then strict UTF-8.
 */
export function bytesToText(bytes: Uint8Array): { text: string; encoding: TextEncodingName } | null {
  if (bytes.length >= 4 && bytes.length % 2 === 0) {
    let zeros = 0;
    for (let i = 1; i < bytes.length; i += 2) if (bytes[i] === 0) zeros++;
    if (zeros / (bytes.length / 2) >= 0.9) {
      const text = new TextDecoder("utf-16le").decode(bytes);
      if (isPrintableText(text)) return { text, encoding: "UTF-16LE" };
    }
  }
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
    if (isPrintableText(text)) return { text, encoding: "UTF-8" };
  } catch {
    // not UTF-8
  }
  return null;
}

/** Parse JSON, returning undefined instead of throwing. */
export function tryParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}
