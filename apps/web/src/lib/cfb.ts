/**
 * A read-only reader for Compound File Binary files (MS-CFB), the container format of Outlook .msg
 * files: a small FAT file system of storages (folders) and streams (files). No dependency.
 *
 * The input is untrusted, so every sector chain is checked for loops and bounds, the directory tree
 * for cycles, and the number of entries is capped. It never throws: a damaged file reads as `null`,
 * or as a partial tree plus warnings.
 */

const SIGNATURE = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const ENDOFCHAIN = 0xfffffffe;
const FREESECT = 0xffffffff;
const MAXREGSECT = 0xfffffffa;
const NOSTREAM = 0xffffffff;

/** Most directory entries read; an Outlook message with a few hundred attachments stays well below. */
export const MAX_CFB_ENTRIES = 20_000;
/** Deepest nesting of storages followed (embedded messages nest a few levels). */
export const MAX_CFB_DEPTH = 16;

export interface CfbEntry {
  name: string;
  kind: "root" | "storage" | "stream";
  children: CfbEntry[];
  /** Declared size of a stream; 0 for storages. */
  size: number;
  /** The stream's bytes (empty for storages). Read on demand, truncated if the file is damaged. */
  read(): Uint8Array<ArrayBuffer>;
}

export interface CfbFile {
  root: CfbEntry;
  warnings: string[];
}

/** True if the bytes start with the compound file signature (.msg, and old .doc/.xls/.ppt). */
export function isCfb(bytes: Uint8Array): boolean {
  return bytes.length >= 512 && SIGNATURE.every((b, i) => bytes[i] === b);
}

interface RawEntry {
  name: string;
  type: number;
  left: number;
  right: number;
  child: number;
  start: number;
  size: number;
}

/** Parse a compound file. Returns null if it isn't one, or its header or directory can't be read. */
export function readCfb(bytes: Uint8Array): CfbFile | null {
  try {
    return parse(bytes);
  } catch {
    return null;
  }
}

function parse(bytes: Uint8Array): CfbFile | null {
  if (!isCfb(bytes)) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u32 = (off: number) => (off + 4 <= bytes.length ? view.getUint32(off, true) : ENDOFCHAIN);
  const warnings: string[] = [];
  const warn = (w: string) => {
    if (!warnings.includes(w)) warnings.push(w);
  };

  if (view.getUint16(0x1c, true) !== 0xfffe) return null;
  const sectorShift = view.getUint16(0x1e, true);
  const miniShift = view.getUint16(0x20, true);
  if (sectorShift !== 9 && sectorShift !== 12) return null;
  if (miniShift !== 6) return null;
  const sectorSize = 1 << sectorShift;
  const miniSize = 1 << miniShift;
  const sectorCount = Math.max(0, Math.floor((bytes.length - sectorSize) / sectorSize) + (bytes.length % sectorSize ? 1 : 0));
  const sectorOffset = (s: number) => (s + 1) * sectorSize;

  const numFat = u32(0x2c);
  const firstDir = u32(0x30);
  const miniCutoff = u32(0x38);
  const firstMiniFat = u32(0x3c);
  const firstDifat = u32(0x44);

  // DIFAT: where the FAT sectors are. 109 entries in the header, then a chain of DIFAT sectors.
  const fatSectors: number[] = [];
  for (let i = 0; i < 109 && fatSectors.length < numFat; i++) {
    const s = u32(0x4c + i * 4);
    if (s <= MAXREGSECT) fatSectors.push(s);
  }
  const perDifat = sectorSize / 4 - 1;
  const seenDifat = new Set<number>();
  for (let d = firstDifat; d <= MAXREGSECT && fatSectors.length < numFat; ) {
    if (seenDifat.has(d) || d >= sectorCount) {
      warn("The file's sector table is damaged; some parts may be missing.");
      break;
    }
    seenDifat.add(d);
    for (let i = 0; i < perDifat && fatSectors.length < numFat; i++) {
      const s = u32(sectorOffset(d) + i * 4);
      if (s <= MAXREGSECT) fatSectors.push(s);
    }
    d = u32(sectorOffset(d) + perDifat * 4);
  }

  const fat = new Uint32Array(fatSectors.length * (sectorSize / 4));
  fatSectors.forEach((s, i) => {
    for (let j = 0; j < sectorSize / 4; j++) fat[i * (sectorSize / 4) + j] = u32(sectorOffset(s) + j * 4);
  });

  /** Follow a chain through `table`, stopping at a loop, a bad index or `limit` links. */
  const chain = (start: number, table: Uint32Array, limit: number): number[] => {
    const out: number[] = [];
    const seen = new Set<number>();
    for (let s = start; s !== ENDOFCHAIN && s !== FREESECT; s = table[s]!) {
      if (s > MAXREGSECT || s >= table.length || seen.has(s) || out.length >= limit) {
        warn("The file's sector table is damaged; some parts may be missing.");
        break;
      }
      seen.add(s);
      out.push(s);
    }
    return out;
  };

  const readChain = (start: number, size: number): Uint8Array<ArrayBuffer> => {
    const sectors = chain(start, fat, Math.ceil(size / sectorSize) + 1);
    const out = new Uint8Array(Math.min(size, sectors.length * sectorSize));
    sectors.forEach((s, i) => {
      const from = sectorOffset(s);
      const part = bytes.subarray(from, Math.min(from + sectorSize, bytes.length));
      out.set(part.subarray(0, Math.min(part.length, out.length - i * sectorSize)), i * sectorSize);
    });
    return out;
  };

  // Directory: 128-byte entries along the directory chain.
  const dirSectors = chain(firstDir, fat, Math.ceil(MAX_CFB_ENTRIES / (sectorSize / 128)));
  const raw: RawEntry[] = [];
  for (const s of dirSectors) {
    for (let off = sectorOffset(s); off + 128 <= Math.min(sectorOffset(s) + sectorSize, bytes.length); off += 128) {
      const nameLen = Math.min(64, view.getUint16(off + 0x40, true));
      let name = "";
      for (let i = 0; i + 1 < nameLen - 1; i += 2) name += String.fromCharCode(view.getUint16(off + i, true));
      raw.push({
        name,
        type: bytes[off + 0x42]!,
        left: view.getUint32(off + 0x44, true),
        right: view.getUint32(off + 0x48, true),
        child: view.getUint32(off + 0x4c, true),
        start: view.getUint32(off + 0x74, true),
        // Version 3 files only use the low 32 bits; nothing we read is anywhere near 4 GB.
        size: view.getUint32(off + 0x78, true),
      });
    }
  }
  const rootRaw = raw[0];
  if (!rootRaw || rootRaw.type !== 5) return null;

  // The mini stream (small streams) lives in the root entry's chain; the mini FAT indexes it.
  const miniStream = readChain(rootRaw.start, rootRaw.size);
  const miniFatBytes = readChain(firstMiniFat, chain(firstMiniFat, fat, sectorCount + 1).length * sectorSize);
  const miniFat = new Uint32Array(Math.floor(miniFatBytes.length / 4));
  const mfView = new DataView(miniFatBytes.buffer, miniFatBytes.byteOffset, miniFatBytes.byteLength);
  for (let i = 0; i < miniFat.length; i++) miniFat[i] = mfView.getUint32(i * 4, true);

  const readMini = (start: number, size: number): Uint8Array<ArrayBuffer> => {
    const sectors = chain(start, miniFat, Math.ceil(size / miniSize) + 1);
    const out = new Uint8Array(Math.min(size, sectors.length * miniSize));
    sectors.forEach((s, i) => {
      const part = miniStream.subarray(s * miniSize, s * miniSize + miniSize);
      out.set(part.subarray(0, Math.min(part.length, out.length - i * miniSize)), i * miniSize);
    });
    return out;
  };

  let built = 0;
  const visited = new Set<number>();

  const build = (id: number, depth: number): CfbEntry | null => {
    const r = raw[id];
    if (!r || visited.has(id) || built >= MAX_CFB_ENTRIES) return null;
    visited.add(id);
    built++;
    const kind = r.type === 5 ? "root" : r.type === 1 ? "storage" : r.type === 2 ? "stream" : null;
    if (!kind) return null;
    const children: CfbEntry[] = [];
    if (kind !== "stream" && r.child !== NOSTREAM) {
      if (depth >= MAX_CFB_DEPTH) warn("Storages nested too deep weren't read.");
      else collect(r.child, depth + 1, children);
    }
    const size = kind === "stream" ? r.size : 0;
    let cache: Uint8Array<ArrayBuffer> | undefined;
    return {
      name: r.name,
      kind,
      children,
      size,
      read: () => (cache ??= kind !== "stream" ? new Uint8Array(0) : size < miniCutoff ? readMini(r.start, size) : readChain(r.start, size)),
    };
  };

  // Siblings form a red-black tree: walk it in order, without recursion on the sibling links.
  const collect = (start: number, depth: number, out: CfbEntry[]) => {
    const stack: number[] = [];
    const seen = new Set<number>();
    let id = start;
    while ((id !== NOSTREAM && id < raw.length) || stack.length) {
      while (id !== NOSTREAM && id < raw.length && !seen.has(id)) {
        seen.add(id);
        stack.push(id);
        id = raw[id]!.left;
      }
      const cur = stack.pop();
      if (cur === undefined) break;
      const e = build(cur, depth);
      if (e) out.push(e);
      id = raw[cur]!.right;
      if (seen.has(id)) id = NOSTREAM;
    }
  };

  const root = build(0, 0);
  if (!root) return null;
  if (built >= MAX_CFB_ENTRIES) warn(`Only the first ${MAX_CFB_ENTRIES} entries in the file were read.`);
  return { root, warnings };
}
