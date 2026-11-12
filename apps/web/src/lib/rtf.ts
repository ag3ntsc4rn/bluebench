/**
 * Outlook's compressed RTF body (PR_RTF_COMPRESSED), for .msg files that keep their HTML body only
 * inside it: decompression per [MS-OXRTFCP] and recovery of the original HTML per [MS-OXRTFEX].
 * Pure and bounded; never throws.
 */

/** Largest decompressed body we produce (decompression bombs). */
export const MAX_RTF_BYTES = 4 * 1024 * 1024;

const PREBUF =
  "{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx";

const MAGIC_COMPRESSED = 0x75465a4c; // "LZFu"
const MAGIC_UNCOMPRESSED = 0x414c454d; // "MELA"

/** Decompress PR_RTF_COMPRESSED. Returns the RTF as a binary string (one char per byte), or null. */
export function decompressRtf(data: Uint8Array): string | null {
  if (data.length < 16) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const compSize = view.getUint32(0, true);
  const rawSize = view.getUint32(4, true);
  const magic = view.getUint32(8, true);
  const end = Math.min(data.length, compSize + 4);

  if (magic === MAGIC_UNCOMPRESSED) {
    let s = "";
    for (let i = 16; i < Math.min(end, 16 + rawSize, 16 + MAX_RTF_BYTES); i++) s += String.fromCharCode(data[i]!);
    return s;
  }
  if (magic !== MAGIC_COMPRESSED) return null;

  // A 4096-byte ring buffer, pre-loaded with common RTF text; the output starts after it.
  const dict = new Uint8Array(4096);
  for (let i = 0; i < PREBUF.length; i++) dict[i] = PREBUF.charCodeAt(i);
  let write = PREBUF.length;
  const limit = Math.min(rawSize || MAX_RTF_BYTES, MAX_RTF_BYTES);
  const out: number[] = [];
  let pos = 16;

  outer: while (pos < end && out.length < limit) {
    const flags = data[pos++]!;
    for (let bit = 0; bit < 8 && pos < end; bit++) {
      if (flags & (1 << bit)) {
        if (pos + 1 >= end) break outer;
        const ref = (data[pos]! << 8) | data[pos + 1]!;
        pos += 2;
        const offset = ref >> 4;
        const length = (ref & 0xf) + 2;
        if (offset === write % 4096) break outer; // end marker
        for (let i = 0; i < length && out.length < limit; i++) {
          const b = dict[(offset + i) % 4096]!;
          out.push(b);
          dict[write % 4096] = b;
          write++;
        }
      } else {
        const b = data[pos++]!;
        out.push(b);
        dict[write % 4096] = b;
        write++;
      }
      if (out.length >= limit) break outer;
    }
  }
  let s = "";
  for (let i = 0; i < out.length; i += 0x8000) s += String.fromCharCode(...out.slice(i, i + 0x8000));
  return s;
}

/** True when the RTF was generated from an HTML body (Outlook's "\fromhtml1"). */
export function isHtmlInRtf(rtf: string): boolean {
  return /\\fromhtml1/.test(rtf.slice(0, 2048));
}

/** Destinations that hold RTF bookkeeping, never message text. */
const RTF_DESTINATIONS = new Set([
  "fonttbl", "colortbl", "stylesheet", "info", "pict", "listtable", "listoverridetable", "rsidtbl",
  "generator", "header", "footer", "xmlnstbl", "themedata", "colorschememapping", "latentstyles", "datastore",
]);

const ESCAPES: Record<string, string> = {
  par: "\r\n", line: "\r\n", tab: "\t", lquote: "‘", rquote: "’", ldblquote: "“",
  rdblquote: "”", bullet: "•", endash: "–", emdash: "—", emspace: " ",
  enspace: " ", qmspace: " ",
};

/**
 * Recover the original HTML from HTML-in-RTF: text inside {\*\htmltag…} groups is HTML markup,
 * text under \htmlrtf is RTF-only and dropped, everything else is the HTML's text content.
 * `codepage` decodes \'hh escapes (\ansicpg). Returns null if the RTF doesn't carry HTML.
 */
export function htmlFromRtf(rtf: string, decode: (bytes: Uint8Array, codepage: number) => string): string | null {
  if (!isHtmlInRtf(rtf)) return null;
  const codepage = Number(/\\ansicpg(\d+)/.exec(rtf.slice(0, 2048))?.[1] ?? 1252);

  let out = "";
  let pendingBytes: number[] = [];
  const flush = () => {
    if (pendingBytes.length) out += decode(Uint8Array.from(pendingBytes), codepage);
    pendingBytes = [];
  };
  const emit = (s: string) => {
    flush();
    out += s;
  };

  // Group state: inHtmlTag (inside \*\htmltag), suppressed (\htmlrtf on), skip (ignorable destination).
  interface State {
    tag: boolean;
    rtfOnly: boolean;
    skip: boolean;
    uc: number;
  }
  const stack: State[] = [];
  let st: State = { tag: false, rtfOnly: false, skip: false, uc: 1 };
  let skipChars = 0; // fallback characters to drop after \uN
  const visible = () => !st.skip && (st.tag || !st.rtfOnly);

  const n = rtf.length;
  let i = 0;
  while (i < n) {
    const c = rtf[i]!;
    if (c === "{") {
      stack.push(st);
      st = { ...st };
      i++;
      // {\*\htmltagN …} carries markup; {\*\mhtmltag…} and other {\*\…} destinations are ignored.
      const m = /^\\\*\\(m?htmltag)(-?\d+)? ?/.exec(rtf.slice(i, i + 24));
      if (m) {
        i += m[0].length;
        if (m[1] === "htmltag") {
          st.tag = true;
          st.rtfOnly = false;
        } else st.skip = true;
      } else if (rtf.startsWith("\\*", i)) st.skip = true;
      else {
        // RTF-only header groups (font and colour tables, document info, pictures) aren't content.
        const word = /^\\([a-z]+)/i.exec(rtf.slice(i, i + 24))?.[1];
        if (word && RTF_DESTINATIONS.has(word)) st.skip = true;
      }
      continue;
    }
    if (c === "}") {
      flush();
      st = stack.pop() ?? st;
      i++;
      continue;
    }
    if (c === "\\") {
      const next = rtf[i + 1];
      if (next === undefined) break;
      if (next === "\\" || next === "{" || next === "}") {
        if (skipChars > 0) skipChars--;
        else if (visible()) emit(next);
        i += 2;
        continue;
      }
      if (next === "'") {
        const hex = rtf.slice(i + 2, i + 4);
        i += 4;
        if (skipChars > 0) {
          skipChars--;
          continue;
        }
        if (/^[0-9a-f]{2}$/i.test(hex) && visible()) pendingBytes.push(parseInt(hex, 16));
        continue;
      }
      if (next === "\r" || next === "\n") {
        if (visible()) emit("\r\n");
        i += 2;
        continue;
      }
      const m = /^\\([a-z]{1,32})(-?\d{1,10})? ?/i.exec(rtf.slice(i, i + 48));
      if (!m) {
        i += 2; // a control symbol like \~ or \-
        if (next === "~" && visible()) emit(" ");
        continue;
      }
      i += m[0].length;
      const word = m[1]!;
      const arg = m[2] === undefined ? undefined : Number(m[2]);
      if (word === "htmlrtf") st.rtfOnly = arg !== 0;
      else if (word === "uc") st.uc = arg ?? 1;
      else if (word === "u" && arg !== undefined) {
        if (visible()) emit(String.fromCharCode(arg < 0 ? arg + 65536 : arg));
        skipChars = st.uc;
      } else if (visible() && ESCAPES[word] && !st.tag) emit(ESCAPES[word]!);
      else if (visible() && st.tag && (word === "par" || word === "line")) emit("\r\n");
      else if (visible() && st.tag && word === "tab") emit("\t");
      continue;
    }
    if (c === "\r" || c === "\n") {
      i++;
      continue;
    }
    if (skipChars > 0) {
      skipChars--;
      i++;
      continue;
    }
    if (visible()) emit(c);
    i++;
  }
  flush();
  return out;
}
