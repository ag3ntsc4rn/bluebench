import { base64ToBytes, bytesToText, findEncodedCommand, sniffFileType } from "@bluebench/shared";
import { hexDump } from "./base64";
import { sortFindings, type Finding } from "./findings";

/** Most layers we peel before giving up. Real droppers rarely use more than three or four. */
export const MAX_LAYERS = 8;
/** Largest decompressed layer we read, so a decompression bomb can't freeze the tab. */
export const MAX_INFLATED_BYTES = 1 << 20;

export type Compression = "gzip" | "deflate";

export interface PsLayer {
  /** How this layer was reached: "Base64 (-EncodedCommand)", "Base64, then gzip". */
  how: string;
  encoding?: string;
  text: string;
}

export interface DecodedPowerShell {
  /** Each decoded layer, outermost first. The last one is the script that would run. */
  layers: PsLayer[];
  /** The innermost layer, when it's a file or binary data rather than text. */
  payload?: { size: number; fileType?: string; hexDump: string };
  /** True if a layer hit MAX_INFLATED_BYTES or MAX_LAYERS. */
  truncated: boolean;
  findings: Finding[];
}

/**
 * Decompress with the browser's DecompressionStream, reading at most `limit` bytes.
 * Returns null if the data isn't valid in that format.
 */
export async function inflate(
  bytes: Uint8Array,
  format: CompressionFormat,
  limit = MAX_INFLATED_BYTES,
): Promise<{ bytes: Uint8Array; truncated: boolean } | null> {
  const ds = new DecompressionStream(format);
  const writer = ds.writable.getWriter();
  writer.write(bytes as Uint8Array<ArrayBuffer>).catch(() => {});
  writer.close().catch(() => {});
  const reader = ds.readable.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      size += value.length;
      if (size >= limit) {
        truncated = true;
        void reader.cancel().catch(() => {});
        break;
      }
    }
  } catch {
    // Not valid in this format, or cut off. A partial result is still worth showing.
    if (size === 0) return null;
    truncated = true;
  }
  const out = new Uint8Array(Math.min(size, limit));
  let off = 0;
  for (const c of chunks) {
    const part = c.subarray(0, out.length - off);
    out.set(part, off);
    off += part.length;
  }
  return { bytes: out, truncated };
}

const B64 = "[A-Za-z0-9+/=\\s]{16,}";
const QUOTED = `(['"])(${B64})\\1`;

/** The base64 that `FromBase64String(…)` decodes, given inline or through a variable assigned earlier. */
export function findInnerBase64(script: string): string | null {
  const inline = new RegExp(`FromBase64String\\s*\\(\\s*${QUOTED}\\s*\\)`, "i").exec(script);
  if (inline) return inline[2]!.replace(/\s+/g, "");
  const viaVar = /FromBase64String\s*\(\s*\$\{?([\w:]+)\}?\s*\)/i.exec(script);
  if (!viaVar) return null;
  const name = viaVar[1]!.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const assigned = new RegExp(`\\$\\{?${name}\\}?\\s*=\\s*${QUOTED}`, "i").exec(script);
  return assigned ? assigned[2]!.replace(/\s+/g, "") : null;
}

/** Which compression a layer's script applies to the bytes it decodes, if any. */
function compressionFor(bytes: Uint8Array, script: string): Compression | null {
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) return "gzip";
  if (/DeflateStream/i.test(script)) return "deflate";
  return null;
}

interface Technique {
  severity: Finding["severity"];
  title: string;
  detail: string;
  test: (all: string) => boolean;
}

const DOWNLOAD = /DownloadString|DownloadData|DownloadFile|Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b|Net\.WebClient|Start-BitsTransfer|Net\.Http\.HttpClient/i;
const RUN_STRING = /\bIEX\b|Invoke-Expression|\.Invoke\(\)|\[ScriptBlock\]::Create/i;

const TECHNIQUES: readonly Technique[] = [
  {
    severity: "critical",
    title: "Tries to switch off malware scanning (AMSI)",
    detail: "It tampers with the Antimalware Scan Interface so security tools can't see what runs next.",
    test: (s) => /AmsiUtils|amsiInitFailed|AmsiScanBuffer|amsi\.dll/i.test(s),
  },
  {
    severity: "critical",
    title: "Changes Microsoft Defender settings",
    detail: "Adding exclusions or turning off real-time protection is a common step before dropping malware.",
    test: (s) => /(?:Add|Set)-MpPreference/i.test(s),
  },
  {
    severity: "critical",
    title: "Downloads code and runs it",
    detail: "A download followed by Invoke-Expression runs whatever the server sends, without saving it to disk first.",
    test: (s) => DOWNLOAD.test(s) && RUN_STRING.test(s),
  },
  {
    severity: "warning",
    title: "Downloads from the internet",
    detail: "Check where it connects to with the indicators below.",
    test: (s) => DOWNLOAD.test(s) && !RUN_STRING.test(s),
  },
  {
    severity: "warning",
    title: "Runs a string as code",
    detail: "Invoke-Expression (IEX) or a script block built at run time: the usual way to run a decoded payload.",
    test: (s) => RUN_STRING.test(s) && !DOWNLOAD.test(s),
  },
  {
    severity: "warning",
    title: "Loads code straight into memory",
    detail: "Reflection or Windows memory APIs let it run a program without writing a file.",
    test: (s) => /Reflection\.Assembly\]::Load|\bVirtualAlloc|\bCreateThread\b|Marshal\]::Copy|GetDelegateForFunctionPointer/i.test(s),
  },
  {
    severity: "warning",
    title: "Sets itself up to run again",
    detail: "Scheduled tasks, Run keys and WMI subscriptions are ways to survive a reboot.",
    test: (s) => /(?:New|Register)-ScheduledTask|schtasks|CurrentVersion\\Run|__EventFilter|CommandLineEventConsumer/i.test(s),
  },
  {
    severity: "warning",
    title: "Hides its window",
    detail: "-WindowStyle Hidden keeps the user from seeing it run.",
    test: (s) => /(?:^|\s)[-/]w\w*\s+["']?(?:h\w*|1)\b/im.test(s),
  },
  {
    severity: "warning",
    title: "Bypasses the execution policy",
    detail: "The execution policy isn't a security boundary, but legitimate tools rarely need to override it.",
    test: (s) => /(?:^|\s)[-/]ex\w*\s+["']?(?:bypass|unrestricted)\b/im.test(s) || /Set-ExecutionPolicy\s+(?:-\w+\s+)*(?:bypass|unrestricted)/i.test(s),
  },
  {
    severity: "info",
    title: "Skips the user's PowerShell profile",
    detail: "-NoProfile is common in scripts and attacks alike.",
    test: (s) => /(?:^|\s)[-/]nop\w*/im.test(s),
  },
];

/**
 * Decode a PowerShell encoded command and peel the layers inside it (base64, gzip, deflate) until it
 * reaches the script that would run. Only decodes: nothing is run, fetched or stored.
 */
export async function decodePowerShell(input: string): Promise<DecodedPowerShell | null> {
  const outer = findEncodedCommand(input);
  const outerBytes = outer && base64ToBytes(outer);
  const outerText = outerBytes && bytesToText(outerBytes);
  if (!outerText) return null;

  const layers: PsLayer[] = [{ how: "Base64 (-EncodedCommand)", encoding: outerText.encoding, text: outerText.text }];
  let payload: DecodedPowerShell["payload"];
  let truncated = false;

  while (layers.length < MAX_LAYERS) {
    const script = layers[layers.length - 1]!.text;
    const inner = findInnerBase64(script);
    let bytes = inner ? base64ToBytes(inner) : null;
    if (!bytes || bytes.length === 0) break;
    let how = "Base64";
    const compression = compressionFor(bytes, script);
    if (compression) {
      // PowerShell's DeflateStream is raw deflate; some droppers use zlib-wrapped data instead.
      const out =
        compression === "gzip" ? await inflate(bytes, "gzip") : ((await inflate(bytes, "deflate-raw")) ?? (await inflate(bytes, "deflate")));
      if (!out) break;
      truncated ||= out.truncated;
      bytes = out.bytes;
      how += `, then ${compression}`;
    }
    const text = sniffFileType(bytes) ? null : bytesToText(bytes);
    if (!text) {
      payload = { size: bytes.length, fileType: sniffFileType(bytes) ?? undefined, hexDump: hexDump(bytes) };
      break;
    }
    layers.push({ how, encoding: text.encoding, text: text.text });
  }
  if (layers.length === MAX_LAYERS && findInnerBase64(layers[MAX_LAYERS - 1]!.text)) truncated = true;

  const all = [input, ...layers.map((l) => l.text)].join("\n");
  const findings: Finding[] = TECHNIQUES.filter((t) => t.test(all)).map(({ severity, title, detail }) => ({ severity, title, detail }));
  if (payload) {
    findings.push({
      severity: payload.fileType ? "critical" : "warning",
      title: payload.fileType ? `Carries a hidden file: ${payload.fileType}` : "Carries binary data",
      detail: payload.fileType ? "Don't save or open it outside a safe analysis environment." : "Often shellcode that's loaded into memory.",
    });
  }
  if (layers.length > 2) {
    findings.push({ severity: "info", title: `Hidden under ${layers.length} layers of encoding`, detail: "Legitimate admin scripts rarely nest encodings." });
  }
  return { layers, payload, truncated, findings: sortFindings(findings) };
}
