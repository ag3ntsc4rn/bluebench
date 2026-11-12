/**
 * Test helpers: a minimal Compound File Binary writer (version 3, 512-byte sectors, small streams in
 * the mini stream as the format requires) and an Outlook .msg builder on top of it. Only used by tests.
 */

export interface CfbNode {
  name: string;
  /** Storage when `children` is set, stream otherwise. */
  children?: CfbNode[];
  data?: Uint8Array;
}

const SECTOR = 512;
const MINI = 64;
const CUTOFF = 4096;
const END = 0xfffffffe;
const FREE = 0xffffffff;
const FATSECT = 0xfffffffd;
const NONE = 0xffffffff;

interface Flat {
  node: CfbNode;
  type: 1 | 2 | 5;
  child: number;
  right: number;
  start: number;
  size: number;
}

export function writeCfb(children: CfbNode[]): Uint8Array<ArrayBuffer> {
  // Flatten: index 0 is the root. Siblings are chained through "right" (a valid, if unbalanced, tree).
  const flat: Flat[] = [{ node: { name: "Root Entry", children }, type: 5, child: NONE, right: NONE, start: END, size: 0 }];
  const add = (nodes: CfbNode[]): number => {
    let first = NONE;
    let prev = -1;
    for (const n of nodes) {
      const id = flat.length;
      flat.push({ node: n, type: n.children ? 1 : 2, child: NONE, right: NONE, start: END, size: n.data?.length ?? 0 });
      if (prev >= 0) flat[prev]!.right = id;
      else first = id;
      prev = id;
      if (n.children) flat[id]!.child = add(n.children);
    }
    return first;
  };
  flat[0]!.child = add(children);

  // Mini stream: small streams, 64-byte sectors.
  const miniFat: number[] = [];
  const miniParts: Uint8Array[] = [];
  const bigStreams: Flat[] = [];
  for (const f of flat) {
    if (f.type !== 2) continue;
    if (f.size === 0) continue;
    if (f.size >= CUTOFF) {
      bigStreams.push(f);
      continue;
    }
    const count = Math.ceil(f.size / MINI);
    f.start = miniFat.length;
    for (let i = 0; i < count; i++) miniFat.push(i === count - 1 ? END : miniFat.length + 1);
    const padded = new Uint8Array(count * MINI);
    padded.set(f.node.data!);
    miniParts.push(padded);
  }
  const miniStream = concat(miniParts);
  flat[0]!.size = miniStream.length;

  const dirSectors = Math.ceil((flat.length * 128) / SECTOR);
  const miniFatSectors = Math.ceil((miniFat.length * 4) / SECTOR);
  const miniStreamSectors = Math.ceil(miniStream.length / SECTOR);
  const bigSectors = bigStreams.reduce((n, f) => n + Math.ceil(f.size / SECTOR), 0);
  const dataSectors = dirSectors + miniFatSectors + miniStreamSectors + bigSectors;
  let fatSectors = 1;
  while (fatSectors * (SECTOR / 4) < fatSectors + dataSectors) fatSectors++;
  if (fatSectors > 109) throw new Error("test CFB too big for a header-only DIFAT");

  const fat = new Uint32Array(fatSectors * (SECTOR / 4)).fill(FREE);
  for (let i = 0; i < fatSectors; i++) fat[i] = FATSECT;
  let next = fatSectors;
  const allocate = (count: number): number => {
    if (count === 0) return END;
    const start = next;
    for (let i = 0; i < count; i++) fat[next + i] = i === count - 1 ? END : next + i + 1;
    next += count;
    return start;
  };
  const dirStart = allocate(dirSectors);
  const miniFatStart = allocate(miniFatSectors);
  flat[0]!.start = miniStream.length ? allocate(miniStreamSectors) : END;
  for (const f of bigStreams) f.start = allocate(Math.ceil(f.size / SECTOR));

  const out = new Uint8Array(SECTOR * (1 + next));
  const view = new DataView(out.buffer);
  out.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
  view.setUint16(0x18, 0x3e, true);
  view.setUint16(0x1a, 3, true);
  view.setUint16(0x1c, 0xfffe, true);
  view.setUint16(0x1e, 9, true);
  view.setUint16(0x20, 6, true);
  view.setUint32(0x2c, fatSectors, true);
  view.setUint32(0x30, dirStart, true);
  view.setUint32(0x38, CUTOFF, true);
  view.setUint32(0x3c, miniFatSectors ? miniFatStart : END, true);
  view.setUint32(0x40, miniFatSectors, true);
  view.setUint32(0x44, END, true);
  for (let i = 0; i < 109; i++) view.setUint32(0x4c + i * 4, i < fatSectors ? i : FREE, true);

  const at = (sector: number) => (sector + 1) * SECTOR;
  fat.forEach((v, i) => view.setUint32(at(0) + i * 4, v, true));
  flat.forEach((f, i) => {
    const off = at(dirStart) + i * 128;
    const name = f.node.name;
    for (let j = 0; j < name.length; j++) view.setUint16(off + j * 2, name.charCodeAt(j), true);
    view.setUint16(off + 0x40, (name.length + 1) * 2, true);
    out[off + 0x42] = f.type;
    out[off + 0x43] = 1; // black
    view.setUint32(off + 0x44, NONE, true);
    view.setUint32(off + 0x48, f.right, true);
    view.setUint32(off + 0x4c, f.child, true);
    view.setUint32(off + 0x74, f.type === 1 ? 0 : f.start, true);
    view.setUint32(off + 0x78, f.size, true);
  });
  const miniFatBytes = new Uint8Array(miniFatSectors * SECTOR).fill(0xff);
  const mfv = new DataView(miniFatBytes.buffer);
  miniFat.forEach((v, i) => mfv.setUint32(i * 4, v, true));
  out.set(miniFatBytes, at(miniFatStart));
  if (miniStream.length) out.set(miniStream, at(flat[0]!.start));
  for (const f of bigStreams) out.set(f.node.data!, at(f.start));
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

// --- .msg builder ---

const hex4 = (n: number) => n.toString(16).toUpperCase().padStart(4, "0");

export type MsgValue =
  | { unicode: string }
  | { ansi: Uint8Array }
  | { binary: Uint8Array }
  | { long: number }
  | { time: Date };

export interface MsgSpec {
  props: Record<number, MsgValue>;
  recipients?: Record<number, MsgValue>[];
  attachments?: (Record<number, MsgValue> & { embedded?: MsgSpec })[];
}

function utf16(s: string): Uint8Array {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    out[i * 2] = s.charCodeAt(i) & 0xff;
    out[i * 2 + 1] = s.charCodeAt(i) >> 8;
  }
  return out;
}

function propNodes(props: Record<number, MsgValue>, headerLen: number): CfbNode[] {
  const nodes: CfbNode[] = [];
  const fixed: Uint8Array[] = [new Uint8Array(headerLen)];
  for (const [idText, v] of Object.entries(props)) {
    const id = Number(idText);
    if ("unicode" in v) nodes.push({ name: `__substg1.0_${hex4(id)}001F`, data: utf16(v.unicode) });
    else if ("ansi" in v) nodes.push({ name: `__substg1.0_${hex4(id)}001E`, data: v.ansi });
    else if ("binary" in v) nodes.push({ name: `__substg1.0_${hex4(id)}0102`, data: v.binary });
    else {
      const e = new Uint8Array(16);
      const dv = new DataView(e.buffer);
      if ("long" in v) {
        dv.setUint32(0, (id << 16) | 0x0003, true);
        dv.setInt32(8, v.long, true);
      } else {
        dv.setUint32(0, ((id << 16) | 0x0040) >>> 0, true);
        const ticks = (v.time.getTime() + 11_644_473_600_000) * 10_000;
        dv.setUint32(8, ticks % 2 ** 32, true);
        dv.setUint32(12, Math.floor(ticks / 2 ** 32), true);
      }
      fixed.push(e);
    }
  }
  nodes.push({ name: "__properties_version1.0", data: concat(fixed) });
  return nodes;
}

function msgNodes(spec: MsgSpec, headerLen: number): CfbNode[] {
  const nodes = propNodes(spec.props, headerLen);
  (spec.recipients ?? []).forEach((r, i) =>
    nodes.push({ name: `__recip_version1.0_#${i.toString(16).toUpperCase().padStart(8, "0")}`, children: propNodes(r, 8) }),
  );
  (spec.attachments ?? []).forEach((a, i) => {
    const { embedded, ...props } = a;
    const children = propNodes(props, 8);
    if (embedded) children.push({ name: "__substg1.0_3701000D", children: msgNodes(embedded, 24) });
    nodes.push({ name: `__attach_version1.0_#${i.toString(16).toUpperCase().padStart(8, "0")}`, children });
  });
  return nodes;
}

/** Build an Outlook .msg file from MAPI properties. */
export function writeMsg(spec: MsgSpec): Uint8Array<ArrayBuffer> {
  return writeCfb(msgNodes(spec, 32));
}
