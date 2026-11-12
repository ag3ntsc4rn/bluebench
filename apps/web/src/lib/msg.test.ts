import { describe, expect, it } from "vitest";
import { isCfb, readCfb } from "./cfb";
import { analyzeHeaders } from "./email-headers";
import { codepageLabel, isOpenableMessage, lcidCodepage, parseMessageFile, parseMsg } from "./msg";
import { decompressRtf, htmlFromRtf } from "./rtf";
import { writeCfb, writeMsg, type MsgSpec } from "./test-msg";
import { collectLinks, readHtml } from "./triage";

const enc = (s: string) => new TextEncoder().encode(s);
const latin1 = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));

// MAPI property IDs used below.
const SUBJECT = 0x0037;
const SUBMIT_TIME = 0x0039;
const SENT_REP_NAME = 0x0042;
const TRANSPORT_HEADERS = 0x007d;
const SENDER_NAME = 0x0c1a;
const SENDER_SMTP = 0x5d01;
const SENT_REP_SMTP = 0x5d02;
const BODY = 0x1000;
const RTF = 0x1009;
const HTML = 0x1013;
const MESSAGE_ID = 0x1035;
const INTERNET_CPID = 0x3fde;
const LOCALE_ID = 0x3ff1;
const MESSAGE_CODEPAGE = 0x3ffd;
const DISPLAY_NAME = 0x3001;
const SMTP = 0x39fe;
const RECIP_TYPE = 0x0c15;
const ATTACH_DATA = 0x3701;
const ATTACH_METHOD = 0x3705;
const ATTACH_LONG_FILENAME = 0x3707;
const ATTACH_LONG_PATHNAME = 0x370d;
const ATTACH_MIME = 0x370e;

const HEADERS = [
  "Received: from mail.micros0ft-support.com (mail.micros0ft-support.com [198.51.100.7]) by mx.victim.org; Tue, 08 Oct 2024 10:00:05 +0000",
  "Authentication-Results: mx.victim.org; spf=pass smtp.mailfrom=micros0ft-support.com; dkim=pass header.d=micros0ft-support.com; dmarc=pass header.from=micros0ft-support.com",
  'From: "Microsoft 365 Security" <no-reply@micros0ft-support.com>',
  "To: user@victim.org",
  "Subject: Password expires today",
  "Date: Tue, 08 Oct 2024 10:00:00 +0000",
  "Message-ID: <1@micros0ft-support.com>",
  "Content-Type: multipart/alternative; boundary=x",
  "",
  "",
].join("\r\n");

const PHISH: MsgSpec = {
  props: {
    [SUBJECT]: { unicode: "Password expires today" },
    [TRANSPORT_HEADERS]: { unicode: HEADERS },
    [BODY]: { unicode: "Keep your password: Sign in <https://evil.test/login>" },
    [HTML]: { binary: enc('<p>Keep your password: <a href="https://evil.test/login">https://login.microsoftonline.com/</a></p>') },
    [INTERNET_CPID]: { long: 65001 },
  },
  attachments: [
    {
      [ATTACH_METHOD]: { long: 1 },
      [ATTACH_LONG_FILENAME]: { unicode: "invoice.pdf.html" },
      [ATTACH_MIME]: { unicode: "text/html" },
      [ATTACH_DATA]: { binary: enc("<form action=https://evil.test/p>") },
    },
  ],
};

describe("compound file reader", () => {
  it("reads storages and streams, small (mini stream) and large", () => {
    const big = new Uint8Array(10_000).map((_, i) => i % 251);
    const file = writeCfb([
      { name: "small", data: enc("hello") },
      { name: "folder", children: [{ name: "big", data: big }, { name: "empty", data: new Uint8Array(0) }] },
    ]);
    expect(isCfb(file)).toBe(true);
    const cfb = readCfb(file)!;
    expect(cfb.warnings).toEqual([]);
    expect(cfb.root.children.map((c) => `${c.kind}:${c.name}`)).toEqual(["stream:small", "storage:folder"]);
    expect(new TextDecoder().decode(cfb.root.children[0]!.read())).toBe("hello");
    const folder = cfb.root.children[1]!;
    expect(folder.children[0]!.read()).toEqual(big);
    expect(folder.children[1]!.read().length).toBe(0);
  });

  it("rejects what isn't a compound file", () => {
    expect(readCfb(enc("From: a@b.example\r\n\r\nhi"))).toBeNull();
    expect(readCfb(new Uint8Array(4096))).toBeNull();
  });

  it("never throws or loops on damaged files", () => {
    const good = writeCfb([{ name: "a", data: new Uint8Array(9000).fill(7) }, { name: "b", data: enc("x") }]);
    // Point every FAT entry at itself (a loop), then truncate and scramble.
    const looped = good.slice();
    const view = new DataView(looped.buffer);
    for (let i = 1; i < 128; i++) view.setUint32(512 + i * 4, i, true);
    expect(() => readCfb(looped)?.root.children.map((c) => c.read())).not.toThrow();
    expect(readCfb(looped)?.warnings ?? ["unreadable"]).not.toEqual([]);

    // A directory whose sibling links form a cycle.
    const cyclic = good.slice();
    const cv = new DataView(cyclic.buffer);
    const dir = (cv.getUint32(0x30, true) + 1) * 512;
    cv.setUint32(dir + 128 * 2 + 0x48, 1, true); // entry 2's right sibling → entry 1
    expect(readCfb(cyclic)!.root.children.length).toBe(2);

    for (const cut of [600, 1024, 2000, good.length - 100]) expect(() => readCfb(good.slice(0, cut))).not.toThrow();
    const noise = good.slice();
    for (let i = 512; i < noise.length; i += 7) noise[i] = (i * 31) & 0xff;
    expect(() => parseMessageFile(noise)).not.toThrow();
  });
});

describe("compressed RTF", () => {
  it("decompresses the [MS-OXRTFCP] example", () => {
    const data = Uint8Array.from(
      "2d0000002b0000004c5a4675f1c5c7a703000a007263706731323542320af32068656c090020627705b06c647d0a800fa0".match(/../g)!,
      (h) => parseInt(h, 16),
    );
    expect(decompressRtf(data)).toBe("{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n");
  });

  it("passes uncompressed (MELA) RTF through and rejects other data", () => {
    const rtf = "{\\rtf1 hi}";
    const head = new Uint8Array(16);
    const v = new DataView(head.buffer);
    v.setUint32(0, rtf.length + 12, true);
    v.setUint32(4, rtf.length, true);
    v.setUint32(8, 0x414c454d, true);
    expect(decompressRtf(new Uint8Array([...head, ...latin1(rtf)]))).toBe(rtf);
    expect(decompressRtf(enc("not compressed rtf at all"))).toBeNull();
  });

  it("recovers HTML from HTML-in-RTF, links and escapes included", () => {
    const rtf = [
      "{\\rtf1\\ansi\\ansicpg1252\\fromhtml1 \\deff0{\\fonttbl{\\f0\\fswiss Arial;}}",
      "{\\*\\htmltag19 <html>}{\\*\\htmltag50 <body>}\\htmlrtf {\\htmlrtf0 ",
      '{\\*\\htmltag84 <a href="https://evil.test/login">}\\htmlrtf {\\field{\\*\\fldinst{HYPERLINK "https://evil.test/login"}}',
      "{\\fldrslt\\cf1\\ul \\htmlrtf0 Sign in to Micros\\'f6ft\\htmlrtf }\\htmlrtf0}\\htmlrtf0 {\\*\\htmltag92 </a>}",
      "\\htmlrtf\\par\\htmlrtf0  caf\\u233?{\\*\\mhtmltag84 <a href=\"cid:ignored\">}\\{x\\}",
      "{\\*\\htmltag58 </body>}{\\*\\htmltag27 </html>}}}",
    ].join("\r\n");
    const html = htmlFromRtf(rtf, (b) => new TextDecoder("windows-1252").decode(b))!;
    expect(html).toBe('<html><body><a href="https://evil.test/login">Sign in to Microsöft</a> café{x}</body></html>');
    expect(htmlFromRtf("{\\rtf1\\ansi\\fromtext hi}", () => "")).toBeNull();
  });
});

describe("Outlook .msg", () => {
  it("reads headers, bodies and attachments into the same shape as an .eml", () => {
    const msg = parseMsg(writeMsg(PHISH))!;
    expect(msg.warnings).toEqual([]);
    expect(msg.headers).toContain("Authentication-Results: mx.victim.org; spf=pass");
    expect(msg.text).toEqual(["Keep your password: Sign in <https://evil.test/login>"]);
    expect(msg.html[0]).toContain('href="https://evil.test/login"');
    expect(msg.attachments).toEqual([
      { filename: "invoice.pdf.html", contentType: "text/html", size: 33, bytes: enc("<form action=https://evil.test/p>") },
    ]);
  });

  it("feeds triage: header red flags and link checks work on a .msg", () => {
    const msg = parseMessageFile(writeMsg(PHISH));
    const titles = analyzeHeaders(msg.headers).findings.map((f) => f.title);
    expect(titles).toContain("Name says Microsoft, address doesn't");
    const links = collectLinks(msg, msg.html.map(readHtml));
    expect(links[0]!.findings.map((f) => f.title)).toContain("Link text shows a different site");
  });

  it("rebuilds headers from Outlook's fields when there are no internet headers, without header injection", () => {
    const msg = parseMsg(
      writeMsg({
        props: {
          [SUBJECT]: { unicode: "Invoice\r\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass" },
          [SENT_REP_NAME]: { unicode: 'PayPal "Billing"' },
          [SENT_REP_SMTP]: { unicode: "billing@paypa1.com" },
          [SENDER_NAME]: { unicode: "Mallory" },
          [SENDER_SMTP]: { unicode: "mallory@evil.test" },
          [SUBMIT_TIME]: { time: new Date("2024-10-08T10:00:00Z") },
          [MESSAGE_ID]: { unicode: "<abc@evil.test>" },
          [BODY]: { unicode: "Pay now" },
        },
        recipients: [
          { [DISPLAY_NAME]: { unicode: "Ann" }, [SMTP]: { unicode: "ann@victim.org" }, [RECIP_TYPE]: { long: 1 } },
          { [DISPLAY_NAME]: { unicode: "Bob" }, [SMTP]: { unicode: "bob@victim.org" }, [RECIP_TYPE]: { long: 2 } },
          { [SMTP]: { unicode: "hidden@victim.org" }, [RECIP_TYPE]: { long: 3 } },
        ],
      }),
    )!;
    expect(msg.headers.split("\r\n").filter(Boolean)).toEqual([
      'From: "PayPal Billing" <billing@paypa1.com>',
      'Sender: "Mallory" <mallory@evil.test>',
      'To: "Ann" <ann@victim.org>',
      'Cc: "Bob" <bob@victim.org>',
      "Subject: Invoice Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass",
      "Date: Tue, 08 Oct 2024 10:00:00 +0000",
      "Message-ID: <abc@evil.test>",
    ]);
    expect(msg.warnings[0]).toMatch(/no internet headers/);
    const a = analyzeHeaders(msg.headers);
    expect(a.auth).toEqual([]);
    expect(a.findings.map((f) => f.title)).toContain("Name says PayPal, address doesn't");
  });

  it("reads an HTML body kept only in compressed RTF", () => {
    const rtf = '{\\rtf1\\ansi\\ansicpg1252\\fromhtml1 {\\*\\htmltag84 <a href="https://evil.test/">}\\htmlrtf {\\htmlrtf0 Click\\htmlrtf }\\htmlrtf0 {\\*\\htmltag92 </a>}}';
    const head = new Uint8Array(16);
    const v = new DataView(head.buffer);
    v.setUint32(0, rtf.length + 12, true);
    v.setUint32(4, rtf.length, true);
    v.setUint32(8, 0x414c454d, true);
    const msg = parseMsg(writeMsg({ props: { [TRANSPORT_HEADERS]: { unicode: HEADERS }, [RTF]: { binary: new Uint8Array([...head, ...latin1(rtf)]) } } }))!;
    expect(msg.html).toEqual(['<a href="https://evil.test/">Click</a>']);
  });

  it("decodes ANSI strings with the message's code page, or the locale's", () => {
    const privet = Uint8Array.from([0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2]);
    const subject = (props: MsgSpec["props"]) => /^Subject: (.*)$/m.exec(parseMsg(writeMsg({ props }))!.headers)?.[1];
    expect(subject({ [MESSAGE_CODEPAGE]: { long: 1251 }, [SUBJECT]: { ansi: privet } })).toBe("Привет");
    // Japanese mail: sent as ISO-2022-JP (PR_INTERNET_CPID), stored in CP932 (from the locale).
    const nihongo = Uint8Array.from([0x93, 0xfa, 0x96, 0x7b, 0x8c, 0xea]);
    expect(subject({ [INTERNET_CPID]: { long: 50220 }, [LOCALE_ID]: { long: 1041 }, [SUBJECT]: { ansi: nihongo } })).toBe("日本語");
    expect(subject({ [SUBJECT]: { ansi: Uint8Array.from([0x63, 0x61, 0x66, 0xe9]) } })).toBe("café");
    // Transport headers win over the rebuilt ones.
    expect(parseMsg(writeMsg({ props: { [SUBJECT]: { ansi: privet }, [TRANSPORT_HEADERS]: { unicode: HEADERS } } }))!.headers).toContain("Subject: Password expires today");
    expect(codepageLabel(1251)).toBe("windows-1251");
    expect(codepageLabel(28592)).toBe("iso-8859-2");
    expect(codepageLabel(424242)).toBe("windows-1252");
    expect([lcidCodepage(1041), lcidCodepage(0x0404), lcidCodepage(0x0804), lcidCodepage(1049), lcidCodepage(1033)]).toEqual([932, 950, 936, 1251, 1252]);
  });

  it("opens a message attached to a message, and notes linked attachments", () => {
    const outer = parseMsg(
      writeMsg({
        props: { [TRANSPORT_HEADERS]: { unicode: HEADERS.replace("Password expires today", "FW: report") }, [BODY]: { unicode: "See attached" } },
        attachments: [
          { [ATTACH_METHOD]: { long: 5 }, [DISPLAY_NAME]: { unicode: "Password expires today" }, embedded: PHISH },
          { [ATTACH_METHOD]: { long: 7 }, [ATTACH_LONG_FILENAME]: { unicode: "Q3.xlsx" }, [ATTACH_LONG_PATHNAME]: { unicode: "https://share.evil.test/Q3.xlsx" } },
        ],
      }),
    )!;
    const [embedded] = outer.attachments;
    expect(outer.attachments).toHaveLength(1);
    expect(embedded).toMatchObject({ filename: "Password expires today.msg", contentType: "application/vnd.ms-outlook", size: 0 });
    expect(embedded!.message!.attachments[0]!.filename).toBe("invoice.pdf.html");
    expect(isOpenableMessage(embedded!)).toBe(true);
    expect(outer.warnings).toEqual(["Q3.xlsx is a link, not a file: https://share.evil.test/Q3.xlsx."]);
    expect(outer.text).toContain("https://share.evil.test/Q3.xlsx");
  });

  it("opens a .msg attached to an .eml, and falls back for other compound files", () => {
    const file = writeMsg(PHISH);
    expect(isOpenableMessage({ contentType: "application/octet-stream", bytes: file })).toBe(true);
    expect(isOpenableMessage({ contentType: "application/octet-stream", bytes: enc("plain") })).toBe(false);
    const doc = writeCfb([{ name: "WordDocument", data: enc("x") }]);
    expect(parseMsg(doc)).toBeNull();
    expect(parseMessageFile(doc).warnings[0]).toMatch(/not an Outlook message/);
    expect(parseMessageFile(enc("From: a@b.example\r\nSubject: hi\r\n\r\nbody")).headers).toContain("Subject: hi");
  });
});
