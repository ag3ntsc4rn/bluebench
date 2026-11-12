import { readCfb, isCfb, type CfbEntry } from "./cfb";
import { decodeCharset, MAX_MIME_PARTS, parseMime, type MimeAttachment, type ParsedMessage } from "./mime";
import { decompressRtf, htmlFromRtf } from "./rtf";

/**
 * Outlook .msg files ([MS-OXMSG]): a compound file whose streams are MAPI properties. We read the
 * same things the MIME parser does (header block, text and HTML bodies, attachments) into a
 * `ParsedMessage`, so the rest of phishing triage doesn't know the difference. Runs in the browser,
 * no dependency, never throws. Nothing is opened, run or fetched.
 */

/** Embedded messages (a message attached to a message) followed this deep. */
export const MAX_MSG_DEPTH = 3;

// Property IDs (high 16 bits of a property tag).
const P = {
  subject: 0x0037,
  clientSubmitTime: 0x0039,
  sentRepresentingName: 0x0042,
  sentRepresentingAddrType: 0x0064,
  sentRepresentingEmail: 0x0065,
  transportHeaders: 0x007d,
  senderName: 0x0c1a,
  senderAddrType: 0x0c1e,
  senderEmail: 0x0c1f,
  displayTo: 0x0e04,
  displayCc: 0x0e03,
  deliveryTime: 0x0e06,
  messageFlags: 0x0e07,
  body: 0x1000,
  rtfCompressed: 0x1009,
  html: 0x1013,
  internetMessageId: 0x1035,
  inReplyTo: 0x1042,
  senderSmtp: 0x5d01,
  sentRepresentingSmtp: 0x5d02,
  recipientType: 0x0c15,
  displayName: 0x3001,
  emailAddress: 0x3003,
  addrType: 0x3002,
  smtpAddress: 0x39fe,
  attachData: 0x3701,
  attachFilename: 0x3704,
  attachMethod: 0x3705,
  attachLongFilename: 0x3707,
  attachPathname: 0x3708,
  attachLongPathname: 0x370d,
  attachMimeTag: 0x370e,
  internetCodepage: 0x3fde,
  localeId: 0x3ff1,
  messageCodepage: 0x3ffd,
} as const;

// Property types (low 16 bits).
const PT_LONG = 0x0003;
const PT_STRING8 = 0x001e;
const PT_UNICODE = 0x001f;
const PT_SYSTIME = 0x0040;
const PT_BINARY = 0x0102;
const PT_OBJECT = 0x000d;

const ATTACH_BY_VALUE = 1;
const ATTACH_EMBEDDED_MSG = 5;
const ATTACH_OLE = 6;

/**
 * The ANSI code page Windows uses for a locale (LCID), for 8-bit strings in a .msg without
 * PR_MESSAGE_CODEPAGE. Keyed by primary language; Chinese depends on the region.
 */
export function lcidCodepage(lcid: number): number {
  const lang = lcid & 0x3ff;
  if (lang === 0x04) return [0x0404, 0x0c04, 0x1404].includes(lcid & 0xffff) ? 950 : 936;
  const byLang: Record<number, number> = {
    0x11: 932, 0x12: 949, 0x1e: 874, 0x08: 1253, 0x1f: 1254, 0x0d: 1255, 0x01: 1256, 0x29: 1256, 0x20: 1256,
    0x25: 1257, 0x26: 1257, 0x27: 1257, 0x2a: 1258,
    0x19: 1251, 0x22: 1251, 0x02: 1251, 0x23: 1251, 0x2f: 1251, 0x3f: 1251, 0x44: 1251,
    0x15: 1250, 0x05: 1250, 0x1b: 1250, 0x0e: 1250, 0x18: 1250, 0x1a: 1250, 0x24: 1250, 0x1c: 1250,
  };
  return byLang[lang] ?? 1252;
}

/** Windows code page number → WHATWG encoding label. Unknown ones fall back to windows-1252. */
export function codepageLabel(cp: number | undefined): string {
  if (!cp) return "windows-1252";
  if (cp >= 1250 && cp <= 1258) return `windows-${cp}`;
  if (cp >= 28591 && cp <= 28606) return `iso-8859-${cp - 28590}`;
  const known: Record<number, string> = {
    65001: "utf-8", 20127: "windows-1252", 874: "windows-874", 932: "shift_jis", 936: "gbk", 54936: "gb18030",
    949: "euc-kr", 950: "big5", 51932: "euc-jp", 50220: "iso-2022-jp", 50221: "iso-2022-jp", 50222: "iso-2022-jp",
    866: "ibm866", 20866: "koi8-r", 21866: "koi8-u", 10000: "macintosh", 1200: "utf-16le", 1201: "utf-16be",
  };
  return known[cp] ?? "windows-1252";
}

const hex4 = (n: number) => n.toString(16).toUpperCase().padStart(4, "0");

interface Props {
  /** Variable-length properties: one stream each, `__substg1.0_<ID><TYPE>`. */
  streams: Map<string, CfbEntry>;
  /** Fixed-size properties from `__properties_version1.0`: id → (type, 8 value bytes). */
  fixed: Map<number, { type: number; value: DataView }>;
  codepage: string;
}

function readProps(storage: CfbEntry, headerLen: number, inheritedCodepage?: string): Props {
  const streams = new Map<string, CfbEntry>();
  for (const c of storage.children) if (c.name.startsWith("__substg1.0_")) streams.set(c.name.slice(12).toUpperCase(), c);
  const fixed = new Map<number, { type: number; value: DataView }>();
  const propStream = storage.children.find((c) => c.name === "__properties_version1.0" && c.kind === "stream");
  if (propStream) {
    const b = propStream.read();
    const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
    for (let off = headerLen; off + 16 <= b.length; off += 16) {
      const tag = view.getUint32(off, true);
      fixed.set(tag >>> 16, { type: tag & 0xffff, value: new DataView(b.buffer, b.byteOffset + off + 8, 8) });
    }
  }
  const props: Props = { streams, fixed, codepage: inheritedCodepage ?? "windows-1252" };
  // 8-bit strings are in the message's ANSI code page; PR_INTERNET_CPID is the encoding the mail was
  // sent in (it applies to the HTML body), which can differ (ISO-2022-JP mail stored as CP932).
  const cp = long(props, P.messageCodepage);
  const locale = long(props, P.localeId);
  if (cp) props.codepage = codepageLabel(cp);
  else if (locale) props.codepage = codepageLabel(lcidCodepage(locale));
  return props;
}

function long(p: Props, id: number): number | undefined {
  const f = p.fixed.get(id);
  return f && f.type === PT_LONG ? f.value.getInt32(0, true) : undefined;
}

function time(p: Props, id: number): Date | undefined {
  const f = p.fixed.get(id);
  if (!f || f.type !== PT_SYSTIME) return undefined;
  // FILETIME: 100 ns ticks since 1601-01-01 UTC.
  const ticks = f.value.getUint32(4, true) * 2 ** 32 + f.value.getUint32(0, true);
  const ms = ticks / 10_000 - 11_644_473_600_000;
  const d = new Date(ms);
  return Number.isFinite(ms) && ms > 0 && !Number.isNaN(d.getTime()) ? d : undefined;
}

function binary(p: Props, id: number): Uint8Array<ArrayBuffer> | undefined {
  return p.streams.get(hex4(id) + hex4(PT_BINARY))?.read();
}

function str(p: Props, id: number): string | undefined {
  const u = p.streams.get(hex4(id) + hex4(PT_UNICODE));
  if (u) return new TextDecoder("utf-16le").decode(u.read()).replace(/\0+$/, "");
  const a = p.streams.get(hex4(id) + hex4(PT_STRING8));
  if (a) return decodeCharset(a.read(), p.codepage).replace(/\0+$/, "");
  return undefined;
}

/** One line, no control characters: a value from the file can't add or break header lines. */
function oneLine(s: string | undefined): string {
  return (s ?? "").replace(/[\x00-\x1f\x7f]+/g, " ").trim();
}

/** An SMTP address from the SMTP-specific property, or the generic one when its type is SMTP. */
function smtp(p: Props, smtpId: number, emailId: number, typeId: number): string {
  const direct = oneLine(str(p, smtpId));
  if (direct.includes("@")) return direct;
  const email = oneLine(str(p, emailId));
  const type = oneLine(str(p, typeId)).toUpperCase();
  return (type === "SMTP" || type === "") && /^[^\s@<>]+@[^\s@<>]+$/.test(email) ? email : "";
}

function mailbox(name: string, address: string): string {
  const n = name.replace(/["\\]/g, "");
  if (!address) return n ? `"${n}"` : "";
  return n && n.toLowerCase() !== address.toLowerCase() ? `"${n}" <${address}>` : `<${address}>`;
}

/** Recipients by type (1 To, 2 Cc, 3 Bcc), as header values. */
function recipients(storage: CfbEntry, codepage: string): { to: string[]; cc: string[] } {
  const to: string[] = [];
  const cc: string[] = [];
  for (const r of storage.children) {
    if (r.kind !== "storage" || !r.name.startsWith("__recip_version1.0_")) continue;
    const p = readProps(r, 8, codepage);
    const box = mailbox(oneLine(str(p, P.displayName)), smtp(p, P.smtpAddress, P.emailAddress, P.addrType));
    if (!box) continue;
    const type = long(p, P.recipientType) ?? 1;
    if (type === 1) to.push(box);
    else if (type === 2) cc.push(box);
  }
  return { to, cc };
}

/** RFC 5322 date, e.g. "Tue, 08 Oct 2024 10:00:00 +0000". */
function rfcDate(d: Date): string {
  return d.toUTCString().replace(/GMT$/, "+0000");
}

/** Message headers rebuilt from Outlook's properties, for a .msg saved without its internet headers. */
function synthesizeHeaders(p: Props, storage: CfbEntry): string {
  const lines: string[] = [];
  const add = (name: string, value: string) => {
    if (value) lines.push(`${name}: ${value}`);
  };
  const fromName = oneLine(str(p, P.sentRepresentingName) ?? str(p, P.senderName));
  const fromAddr =
    smtp(p, P.sentRepresentingSmtp, P.sentRepresentingEmail, P.sentRepresentingAddrType) ||
    smtp(p, P.senderSmtp, P.senderEmail, P.senderAddrType);
  add("From", mailbox(fromName, fromAddr));
  const senderAddr = smtp(p, P.senderSmtp, P.senderEmail, P.senderAddrType);
  // "Sent on behalf of": the sender differs from who it claims to be from.
  if (senderAddr && fromAddr && senderAddr.toLowerCase() !== fromAddr.toLowerCase())
    add("Sender", mailbox(oneLine(str(p, P.senderName)), senderAddr));
  const r = recipients(storage, p.codepage);
  add("To", r.to.join(", ") || oneLine(str(p, P.displayTo)));
  add("Cc", r.cc.join(", ") || oneLine(str(p, P.displayCc)));
  add("Subject", oneLine(str(p, P.subject)));
  const date = time(p, P.clientSubmitTime) ?? time(p, P.deliveryTime);
  if (date) add("Date", rfcDate(date));
  add("Message-ID", oneLine(str(p, P.internetMessageId)));
  add("In-Reply-To", oneLine(str(p, P.inReplyTo)));
  return lines.length ? `${lines.join("\r\n")}\r\n` : "";
}

/** The header block of PR_TRANSPORT_MESSAGE_HEADERS: up to its first blank line. */
function transportHeaderBlock(raw: string): string {
  const text = raw.replace(/^\s+/, "");
  const end = text.search(/\r?\n\r?\n/);
  return end < 0 ? text : text.slice(0, end + 1);
}

interface Ctx {
  depth: number;
  parts: number;
}

function parseStorage(storage: CfbEntry, headerLen: number, ctx: Ctx, codepage?: string): ParsedMessage {
  const out: ParsedMessage = { headers: "", text: [], html: [], attachments: [], warnings: [] };
  const p = readProps(storage, headerLen, codepage);

  const transport = str(p, P.transportHeaders);
  if (transport?.trim()) out.headers = transportHeaderBlock(transport);
  else {
    out.headers = synthesizeHeaders(p, storage);
    // MSGFLAG_UNSENT: a draft never sent, so it has no sender or delivery path at all.
    if ((long(p, P.messageFlags) ?? 0) & 0x8) out.warnings.push("Outlook marks this message as unsent (a draft), so it has no sender.");
    else out.warnings.push(
      "This .msg has no internet headers (usual for drafts and sent items, and some saved messages), so SPF, DKIM, DMARC and the hop path can't be checked. The sender and recipients shown come from Outlook's own fields.",
    );
  }

  const body = str(p, P.body);
  if (body?.trim()) out.text.push(body);

  const htmlBin = binary(p, P.html);
  const htmlStr = htmlBin ? undefined : str(p, P.html);
  if (htmlBin?.length) {
    const metaCharset = /<meta[^>]+charset\s*=\s*["']?([\w-]+)/i.exec(new TextDecoder("latin1").decode(htmlBin.subarray(0, 2048)))?.[1];
    // Outlook pads some HTML bodies with NULs.
    const cpid = long(p, P.internetCodepage);
    out.html.push(decodeCharset(htmlBin, cpid ? codepageLabel(cpid) : (metaCharset ?? "utf-8")).replace(/\0+$/, ""));
  } else if (htmlStr?.trim()) out.html.push(htmlStr);
  else {
    const rtfBin = binary(p, P.rtfCompressed);
    const rtf = rtfBin ? decompressRtf(rtfBin) : null;
    const html = rtf ? htmlFromRtf(rtf, (bytes, cp) => decodeCharset(bytes, codepageLabel(cp))) : null;
    if (html?.trim()) out.html.push(html);
    else if (rtfBin && !body?.trim()) out.warnings.push("The body is stored only as Outlook rich text, which isn't analysed.");
  }

  for (const a of storage.children) {
    if (a.kind !== "storage" || !a.name.startsWith("__attach_version1.0_")) continue;
    if (++ctx.parts > MAX_MIME_PARTS) {
      out.warnings.push(`Only the first ${MAX_MIME_PARTS} attachments were looked at.`);
      break;
    }
    readAttachment(a, p.codepage, ctx, out);
  }
  return out;
}

function readAttachment(storage: CfbEntry, codepage: string, ctx: Ctx, out: ParsedMessage) {
  const p = readProps(storage, 8, codepage);
  const method = long(p, P.attachMethod) ?? ATTACH_BY_VALUE;
  const name = oneLine(str(p, P.attachLongFilename) || str(p, P.attachFilename) || str(p, P.displayName));
  const contentType = oneLine(str(p, P.attachMimeTag)).toLowerCase() || "application/octet-stream";

  if (method === ATTACH_EMBEDDED_MSG) {
    const inner = p.streams.get(hex4(P.attachData) + hex4(PT_OBJECT));
    if (!inner || inner.kind !== "storage") {
      out.warnings.push(`The attached message ${name || "(no name)"} couldn't be read.`);
      return;
    }
    if (ctx.depth + 1 > MAX_MSG_DEPTH) {
      out.warnings.push(`Messages attached more than ${MAX_MSG_DEPTH} levels deep weren't read.`);
      return;
    }
    const message = parseStorage(inner, 24, { depth: ctx.depth + 1, parts: ctx.parts }, codepage);
    const subject = /^subject:\s*(.*)$/im.exec(message.headers)?.[1]?.trim();
    const attachment: MimeAttachment = {
      filename: /\.msg$/i.test(name) ? name : `${name || subject || "attached message"}.msg`,
      contentType: "application/vnd.ms-outlook",
      size: 0,
      bytes: new Uint8Array(0),
      message,
    };
    out.attachments.push(attachment);
    return;
  }

  if (method === ATTACH_OLE) {
    out.warnings.push(`${name || "An attachment"} is an embedded OLE object, which isn't analysed.`);
    return;
  }

  if (method !== ATTACH_BY_VALUE) {
    // By reference: the "attachment" is a path or link. Its target goes into the indicators.
    const path = oneLine(str(p, P.attachLongPathname) || str(p, P.attachPathname));
    out.warnings.push(`${name || "An attachment"} is a link, not a file${path ? `: ${path}` : ""}.`);
    if (path) out.text.push(path);
    return;
  }

  const bytes = binary(p, P.attachData) ?? new Uint8Array(0);
  out.attachments.push({ filename: name || "(no name)", contentType, size: bytes.length, bytes });
}

/** Parse an Outlook .msg file. Returns null if the bytes aren't a readable .msg. */
export function parseMsg(bytes: Uint8Array): ParsedMessage | null {
  const cfb = readCfb(bytes);
  if (!cfb) return null;
  // Every .msg has a properties stream at the root; old .doc/.xls files don't.
  if (!cfb.root.children.some((c) => c.name === "__properties_version1.0")) return null;
  try {
    const msg = parseStorage(cfb.root, 32, { depth: 0, parts: 0 });
    msg.warnings.push(...cfb.warnings);
    return msg;
  } catch {
    return { headers: "", text: [], html: [], attachments: [], warnings: ["This Outlook message couldn't be read."] };
  }
}

/** Parse a dropped or attached message file: Outlook .msg or MIME (.eml). Never throws. */
export function parseMessageFile(bytes: Uint8Array): ParsedMessage {
  if (isCfb(bytes)) {
    return (
      parseMsg(bytes) ?? {
        headers: "",
        text: [],
        html: [],
        attachments: [],
        warnings: ["This is an Office compound file, but not an Outlook message we can read. In Outlook, save it as .eml, or paste the message source."],
      }
    );
  }
  return parseMime(bytes);
}

/** True when an attachment is itself a message that triage can open. */
export function isOpenableMessage(a: Pick<MimeAttachment, "contentType" | "bytes" | "message">): boolean {
  return Boolean(a.message) || a.contentType === "message/rfc822" || (isCfb(a.bytes) && parseMsg(a.bytes) !== null);
}
