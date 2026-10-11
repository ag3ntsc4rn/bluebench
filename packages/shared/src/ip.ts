/** Parse a dotted-quad IPv4 address to a uint32. Rejects leading zeros (ambiguous octal). */
export function parseIPv4(input: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(input);
  if (!m) return null;
  let value = 0;
  for (const part of m.slice(1)) {
    if (part.length > 1 && part.startsWith("0")) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = value * 256 + n;
  }
  return value;
}

export function formatIPv4(value: number): string {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join(".");
}

/** Parse an IPv6 address (with optional embedded IPv4 tail) to a 128-bit bigint. No zone IDs. */
export function parseIPv6(input: string): bigint | null {
  if (!/^[0-9a-fA-F:.]+$/.test(input) || !input.includes(":")) return null;
  let s = input;
  const lastColon = s.lastIndexOf(":");
  if (s.slice(lastColon + 1).includes(".")) {
    // Rewrite an embedded IPv4 tail (::ffff:1.2.3.4) as two hex groups.
    const v4 = parseIPv4(s.slice(lastColon + 1));
    if (v4 === null) return null;
    s = `${s.slice(0, lastColon + 1)}${(v4 >>> 16).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const toNums = (part: string) => (part === "" ? [] : part.split(":"));
  const head = toNums(halves[0]!);
  const rest = halves.length === 2 ? toNums(halves[1]!) : [];
  if (![...head, ...rest].every((g) => /^[0-9a-fA-F]{1,4}$/.test(g))) return null;
  const total = head.length + rest.length;
  if (halves.length === 2 ? total > 7 : total !== 8) return null;
  const groups = [...head, ...new Array<string>(8 - total).fill("0"), ...rest];
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16)), 0n);
}

/** Format a 128-bit value in RFC 5952 canonical form (lowercase, longest zero run compressed). */
export function formatIPv6(value: bigint): string {
  const groups = Array.from({ length: 8 }, (_, i) => Number((value >> BigInt((7 - i) * 16)) & 0xffffn));
  let bestStart = -1;
  let bestLen = 1;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) [bestStart, bestLen] = [i, j - i];
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart < 0) return hex.join(":");
  return `${hex.slice(0, bestStart).join(":")}::${hex.slice(bestStart + bestLen).join(":")}`;
}

export type IpAddress = { version: 4; value: number } | { version: 6; value: bigint };

export function parseIp(input: string): IpAddress | null {
  const v4 = parseIPv4(input);
  if (v4 !== null) return { version: 4, value: v4 };
  const v6 = parseIPv6(input);
  return v6 === null ? null : { version: 6, value: v6 };
}

export interface IpClassification {
  /** True for globally routable unicast addresses. */
  global: boolean;
  /** Human-readable range name, e.g. "Private (RFC 1918)". */
  range: string;
}

const V4_RANGES: [string, number, string][] = [
  ["255.255.255.255", 32, "Broadcast"],
  ["0.0.0.0", 8, "This network"],
  ["10.0.0.0", 8, "Private (RFC 1918)"],
  ["100.64.0.0", 10, "Carrier-grade NAT"],
  ["127.0.0.0", 8, "Loopback"],
  ["169.254.169.254", 32, "Cloud metadata service"],
  ["169.254.0.0", 16, "Link-local"],
  ["172.16.0.0", 12, "Private (RFC 1918)"],
  ["192.0.0.0", 24, "IETF protocol assignments"],
  ["192.0.2.0", 24, "Documentation (TEST-NET-1)"],
  ["192.168.0.0", 16, "Private (RFC 1918)"],
  ["198.18.0.0", 15, "Benchmarking"],
  ["198.51.100.0", 24, "Documentation (TEST-NET-2)"],
  ["203.0.113.0", 24, "Documentation (TEST-NET-3)"],
  ["224.0.0.0", 4, "Multicast"],
  ["240.0.0.0", 4, "Reserved"],
];

const V6_RANGES: [string, number, string][] = [
  ["::", 128, "Unspecified"],
  ["::1", 128, "Loopback"],
  ["100::", 64, "Discard-only"],
  ["2001:db8::", 32, "Documentation"],
  ["fc00::", 7, "Private (unique local)"],
  ["fe80::", 10, "Link-local"],
  ["ff00::", 8, "Multicast"],
];

function inV4(value: number, base: string, bits: number): boolean {
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return ((value & mask) >>> 0) === ((parseIPv4(base)! & mask) >>> 0);
}

function inV6(value: bigint, base: string, bits: number): boolean {
  const shift = BigInt(128 - bits);
  return value >> shift === parseIPv6(base)! >> shift;
}

/** Classify an address as global or a named special-purpose range (v4 and v6). */
export function classifyIp(ip: IpAddress): IpClassification {
  if (ip.version === 4) {
    const hit = V4_RANGES.find(([base, bits]) => inV4(ip.value, base, bits));
    return hit ? { global: false, range: hit[2] } : { global: true, range: "Public" };
  }
  const v = ip.value;
  // IPv4-mapped (::ffff:0:0/96) and NAT64 (64:ff9b::/96) embed an IPv4 address: judge that.
  if (inV6(v, "::ffff:0:0", 96) || inV6(v, "64:ff9b::", 96)) {
    const inner = classifyIp({ version: 4, value: Number(v & 0xffffffffn) });
    const prefix = inV6(v, "64:ff9b::", 96) ? "NAT64" : "IPv4-mapped";
    return { global: inner.global, range: `${prefix}: ${inner.range}` };
  }
  const hit = V6_RANGES.find(([base, bits]) => inV6(v, base, bits));
  if (hit) return { global: false, range: hit[2] };
  if (!inV6(v, "2000::", 3)) return { global: false, range: "Reserved" };
  return { global: true, range: "Public" };
}
