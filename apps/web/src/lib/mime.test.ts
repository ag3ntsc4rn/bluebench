import { describe, expect, it } from "vitest";
import {
  decodeBase64,
  decodeCharset,
  decodeQuotedPrintable,
  looksLikeFullMessage,
  MAX_MIME_DEPTH,
  MAX_MIME_PARTS,
  parseHeaderValue,
  parseMime,
} from "./mime";

const crlf = (lines: string[]) => lines.join("\r\n");
const lf = (lines: string[]) => lines.join("\n");
const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

describe("parseHeaderValue", () => {
  it("reads quoted and unquoted parameters", () => {
    expect(parseHeaderValue('Multipart/Mixed; boundary="a;b c"; charset=UTF-8')).toEqual({
      value: "multipart/mixed",
      params: { boundary: "a;b c", charset: "UTF-8" },
    });
    expect(parseHeaderValue("multipart/alternative; boundary=----=_Part_1").params.boundary).toBe("----=_Part_1");
  });

  it("decodes RFC 2231 extended and continued values", () => {
    expect(parseHeaderValue("attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf").params.filename).toBe("résumé.pdf");
    expect(parseHeaderValue("attachment; filename*=iso-8859-1'en'caf%E9.txt").params.filename).toBe("café.txt");
    expect(
      parseHeaderValue("attachment; filename*1*=%20report.docx; filename*0*=UTF-8''Q3%20; filename=fallback.docx").params.filename,
    ).toBe("Q3  report.docx");
    expect(parseHeaderValue('attachment; filename*0="long"; filename*1="name.zip"').params.filename).toBe("longname.zip");
  });
});

describe("transfer and charset decoding", () => {
  it("decodes base64 leniently, ignoring line breaks and junk", () => {
    expect(text(decodeBase64("aGVs\r\nbG8g\nd29y bGQ=\n"))).toBe("hello world");
    expect(text(decodeBase64("aGVsbG8!!"))).toBe("hello");
  });

  it("decodes quoted-printable with soft line breaks", () => {
    expect(decodeQuotedPrintable("caf=E9 =\r\nau lait=3D")).toBe("caf\xe9 au lait=");
    expect(decodeQuotedPrintable("bad =ZZ escape")).toBe("bad =ZZ escape");
  });

  it("falls back to UTF-8 for unknown charsets", () => {
    expect(decodeCharset(new TextEncoder().encode("héllo"), "x-made-up")).toBe("héllo");
    expect(decodeCharset(Uint8Array.of(0x63, 0x61, 0x66, 0xe9), "iso-8859-1")).toBe("café");
  });
});

describe("parseMime", () => {
  it("reads a single-part message", () => {
    const msg = parseMime(crlf(["From: a@example.com", "Subject: hi", "", "Hello there.", "Bye."]));
    expect(msg.headers).toBe("From: a@example.com\r\nSubject: hi");
    expect(msg.text).toEqual(["Hello there.\r\nBye."]);
    expect(msg.html).toEqual([]);
    expect(msg.attachments).toEqual([]);
    expect(msg.warnings).toEqual([]);
  });

  it("reads multipart/alternative", () => {
    const msg = parseMime(
      crlf([
        "From: a@example.com",
        'Content-Type: multipart/alternative; boundary="b1"',
        "",
        "This is a preamble.",
        "--b1",
        "Content-Type: text/plain; charset=utf-8",
        "",
        "Plain body",
        "--b1",
        "Content-Type: text/html; charset=utf-8",
        "",
        "<p>HTML body</p>",
        "--b1--",
        "epilogue",
      ]),
    );
    expect(msg.text).toEqual(["Plain body"]);
    expect(msg.html).toEqual(["<p>HTML body</p>"]);
    expect(msg.warnings).toEqual([]);
  });

  it("reads nested multipart/mixed > multipart/alternative with an attachment", () => {
    const msg = parseMime(
      crlf([
        "From: a@example.com",
        "Content-Type: multipart/mixed; boundary=outer",
        "",
        "--outer",
        "Content-Type: multipart/alternative; boundary=inner",
        "",
        "--inner",
        "Content-Type: text/plain",
        "",
        "Text",
        "--inner",
        "Content-Type: text/html",
        "",
        "<b>HTML</b>",
        "--inner--",
        "--outer",
        "Content-Type: application/pdf; name=invoice.pdf",
        "Content-Disposition: attachment; filename=invoice.pdf",
        "Content-Transfer-Encoding: base64",
        "",
        "JVBERi0xLjQK",
        "--outer--",
      ]),
    );
    expect(msg.text).toEqual(["Text"]);
    expect(msg.html).toEqual(["<b>HTML</b>"]);
    expect(msg.attachments).toHaveLength(1);
    expect(msg.attachments[0]).toMatchObject({ filename: "invoice.pdf", contentType: "application/pdf", size: 9 });
    expect(text(msg.attachments[0]!.bytes)).toBe("%PDF-1.4\n");
  });

  it("decodes base64 and quoted-printable bodies with their charsets", () => {
    const msg = parseMime(
      lf([
        "Content-Type: multipart/alternative; boundary=x",
        "",
        "--x",
        "Content-Type: text/plain; charset=iso-8859-1",
        "Content-Transfer-Encoding: quoted-printable",
        "",
        "Caf=E9 cr=E8me, a long line that is =",
        "soft-wrapped.",
        "--x",
        "Content-Type: text/html; charset=UTF-8",
        "Content-Transfer-Encoding: base64",
        "",
        btoa(String.fromCharCode(...new TextEncoder().encode("<p>Grüße 👋</p>"))),
        "--x",
        "Content-Type: text/plain; charset=windows-1251",
        "Content-Transfer-Encoding: base64",
        "",
        btoa(String.fromCharCode(0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2)),
        "--x",
        "Content-Type: text/plain; charset=no-such-charset",
        "Content-Transfer-Encoding: 8bit",
        "",
        "ünïcödé",
        "--x--",
      ]),
    );
    expect(msg.text).toEqual(["Café crème, a long line that is soft-wrapped.", "Привет", "ünïcödé"]);
    expect(msg.html).toEqual(["<p>Grüße 👋</p>"]);
  });

  it("decodes 8-bit bodies in a file with their declared charset", () => {
    const head = new TextEncoder().encode("Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\n");
    const bytes = new Uint8Array([...head, 0x63, 0x61, 0x66, 0xe9]);
    expect(parseMime(bytes).text).toEqual(["café"]);
  });

  it("decodes encoded-word and RFC 2231 attachment names", () => {
    const msg = parseMime(
      lf([
        "Content-Type: multipart/mixed; boundary=b",
        "",
        "--b",
        'Content-Type: application/octet-stream; name="=?UTF-8?B?0YHRh9C10YIuemlw?="',
        "Content-Disposition: attachment",
        "",
        "data",
        "--b",
        "Content-Type: application/pdf",
        "Content-Disposition: attachment;",
        " filename*=UTF-8''%E2%82%AC%20invoice.pdf",
        "",
        "data",
        "--b",
        "Content-Type: message/rfc822",
        "",
        "From: x@example.com",
        "",
        "Inner",
        "--b--",
      ]),
    );
    expect(msg.attachments.map((a) => a.filename)).toEqual(["счет.zip", "€ invoice.pdf", "attached-message.eml"]);
    expect(msg.attachments[2]!.contentType).toBe("message/rfc822");
  });

  it("treats a text part with a file name as an attachment", () => {
    const msg = parseMime(
      lf(["Content-Type: multipart/mixed; boundary=b", "", "--b", "Content-Type: text/html; name=login.html", "", "<form></form>", "--b--"]),
    );
    expect(msg.html).toEqual([]);
    expect(msg.attachments[0]).toMatchObject({ filename: "login.html", contentType: "text/html" });
  });

  it("shows a multipart with a missing or wrong boundary as plain text", () => {
    const missing = parseMime(lf(["Content-Type: multipart/mixed", "", "--zzz", "body text"]));
    expect(missing.text).toEqual(["--zzz\nbody text"]);
    expect(missing.warnings[0]).toMatch(/boundary/);
    const wrong = parseMime(lf(["Content-Type: multipart/mixed; boundary=nope", "", "--other", "", "body", "--other--"]));
    expect(wrong.text).toHaveLength(1);
    expect(wrong.warnings[0]).toMatch(/boundary/);
  });

  it("copes with a missing closing boundary", () => {
    const msg = parseMime(lf(["Content-Type: multipart/mixed; boundary=b", "", "--b", "", "first", "--b", "", "second (cut short)"]));
    expect(msg.text).toEqual(["first", "second (cut short)"]);
    expect(msg.warnings[0]).toMatch(/closing boundary/);
  });

  it("handles LF-only line endings like CRLF", () => {
    const lines = ["From: a@example.com", "Content-Type: multipart/alternative; boundary=b", "", "--b", "Content-Type: text/plain", "", "Hi", "--b--"];
    expect(parseMime(lf(lines)).text).toEqual(["Hi"]);
    expect(parseMime(crlf(lines)).text).toEqual(["Hi"]);
    expect(parseMime(lf(lines)).headers).toBe("From: a@example.com\nContent-Type: multipart/alternative; boundary=b");
  });

  it("unfolds headers", () => {
    const msg = parseMime(lf(["Content-Type: multipart/mixed;", '\tboundary="folded"', "", "--folded", "", "ok", "--folded--"]));
    expect(msg.text).toEqual(["ok"]);
  });

  it("treats a paste without headers as a plain body", () => {
    const msg = parseMime("Just some text\nhttps://example.com/x");
    expect(msg.headers).toBe("");
    expect(msg.text).toEqual(["Just some text\nhttps://example.com/x"]);
  });

  it(`stops at ${MAX_MIME_DEPTH} levels of nesting`, () => {
    let body = "deep text";
    for (let i = 14; i >= 0; i--) body = `Content-Type: multipart/mixed; boundary=b${i}\n\n--b${i}\n${body}\n--b${i}--`;
    const msg = parseMime(`From: a@example.com\n${body}`);
    expect(msg.text).toEqual([]);
    expect(msg.warnings.some((w) => w.includes(`${MAX_MIME_DEPTH} deep`))).toBe(true);
  });

  it(`stops after ${MAX_MIME_PARTS} parts`, () => {
    const parts = Array.from({ length: 500 }, (_, i) => `--b\nContent-Type: text/plain\n\npart ${i}`).join("\n");
    const msg = parseMime(`Content-Type: multipart/mixed; boundary=b\n\n${parts}\n--b--`);
    expect(msg.text.length).toBe(MAX_MIME_PARTS - 1); // the container counts as one part
    expect(msg.warnings.some((w) => w.includes(`${MAX_MIME_PARTS} parts`))).toBe(true);
  });

  it("never throws on garbage", () => {
    for (const junk of ["", "\r\n\r\n", ":::", "Content-Type: multipart/\n\n--", "Content-Type: ;;;\"\n\n=?x?Q?", String.fromCharCode(...Array.from({ length: 256 }, (_, i) => i))]) {
      expect(() => parseMime(junk)).not.toThrow();
    }
    expect(() => parseMime(Uint8Array.from({ length: 4096 }, (_, i) => (i * 37) % 256))).not.toThrow();
  });
});

describe("looksLikeFullMessage", () => {
  it("needs headers followed by a body", () => {
    expect(looksLikeFullMessage("From: a@example.com\nSubject: x\n\nHello")).toBe(true);
    expect(looksLikeFullMessage("From: a@example.com\nSubject: x\n")).toBe(false);
    expect(looksLikeFullMessage("From: a@example.com\nSubject: x\n\n  \n")).toBe(false);
    expect(looksLikeFullMessage("Hello\n\nworld")).toBe(false);
  });
});
