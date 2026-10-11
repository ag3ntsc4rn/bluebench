import { base64ToBytes, bytesToText, sniffFileType, type TextEncodingName } from "@bluebench/shared";

export interface DecodedBase64 {
  size: number;
  text?: string;
  encoding?: TextEncodingName;
  fileType?: string;
  /** Hex dump of the first HEX_DUMP_LIMIT bytes, for binary content. */
  hexDump?: string;
  truncated: boolean;
}

export const HEX_DUMP_LIMIT = 512;

/** Classic offset / hex / ASCII dump, 16 bytes per line. */
export function hexDump(bytes: Uint8Array, limit = HEX_DUMP_LIMIT): string {
  const lines: string[] = [];
  const end = Math.min(bytes.length, limit);
  for (let off = 0; off < end; off += 16) {
    const row = bytes.subarray(off, Math.min(off + 16, end));
    const hex = Array.from(row, (b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(row, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${off.toString(16).padStart(8, "0")}  ${hex.padEnd(47)}  ${ascii}`);
  }
  return lines.join("\n");
}

export function decodeBase64(input: string): DecodedBase64 | null {
  const bytes = base64ToBytes(input);
  if (!bytes) return null;
  const fileType = sniffFileType(bytes) ?? undefined;
  const text = fileType ? null : bytesToText(bytes);
  if (text) return { size: bytes.length, text: text.text, encoding: text.encoding, truncated: false };
  return { size: bytes.length, fileType, hexDump: hexDump(bytes), truncated: bytes.length > HEX_DUMP_LIMIT };
}
