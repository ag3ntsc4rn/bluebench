import { describe, expect, it } from "vitest";
import { analyzeHeaders } from "./email-headers";
import { parseMime } from "./mime";
import {
  classifyAttachment,
  claimedHost,
  clearHandOff,
  collectLinks,
  handOffMessage,
  linkFindings,
  NO_FLAGS,
  peekHandOff,
  readHtml,
  reportAttachment,
  sha256Hex,
  ticketNote,
  triageFlags,
  triageIndicators,
} from "./triage";

const titles = (f: { title: string }[]) => f.map((x) => x.title);
const bytes = (...b: number[]) => Uint8Array.from(b);
const ascii = (s: string) => new TextEncoder().encode(s);

describe("readHtml (fallback without DOMParser)", () => {
  it("collects links with their visible text, ignoring scripts and styles", () => {
    const html = `<style>a{}</style><script>var a = '<a href="https://evil.test/x">no</a>'</script>
      <p>Hi &amp; welcome</p><a class="btn" href='https://example.com/a?x=1&amp;y=2'><b>Sign</b> in</a>
      <a href=https://example.net/b>https://www.example.org</a><img src="https://tracker.example.com/p.gif">`;
    const r = readHtml(html);
    expect(r.links).toEqual([
      { href: "https://example.com/a?x=1&y=2", text: "Sign in" },
      { href: "https://example.net/b", text: "https://www.example.org" },
    ]);
    expect(r.text).toContain("Hi & welcome");
    expect(r.text).not.toContain("evil.test");
  });
});

describe("linkFindings", () => {
  it("flags link text that shows a different site than the link goes to", () => {
    expect(titles(linkFindings("https://login.example-bank.test/", "https://www.example.com/account"))).toEqual(["Link text shows a different site"]);
    expect(titles(linkFindings("https://evil.test/", "example.com"))).toEqual(["Link text shows a different site"]);
    expect(titles(linkFindings("http://192.0.2.5/login", "www.example.com"))).toContain("Link text shows a different site");
  });

  it("doesn't flag the same registrable domain, or ordinary link text", () => {
    expect(linkFindings("https://mail.example.com/x", "https://www.example.com")).toEqual([]);
    expect(linkFindings("https://a.example.co.uk/", "b.example.co.uk")).toEqual([]);
    expect(linkFindings("https://evil.test/", "Click here")).toEqual([]);
    expect(linkFindings("https://evil.test/", "Read more at example.com today")).toEqual([]);
  });

  it("treats each tenant of a shared host as its own site", () => {
    expect(titles(linkFindings("https://attacker.github.io/", "victim.github.io"))).toEqual(["Link text shows a different site"]);
  });

  it("flags script and data links, even with whitespace hidden in the scheme", () => {
    expect(linkFindings("javascript:alert(1)", "Open")[0]).toMatchObject({ severity: "critical", title: "Link uses a javascript: address" });
    expect(linkFindings(" java\tscript:void(0)", "x")[0]?.title).toBe("Link uses a javascript: address");
    expect(linkFindings("data:text/html;base64,PHA+", "x")[0]?.title).toBe("Link uses a data: address");
    expect(linkFindings("ms-msdt:/id", "x")[0]).toMatchObject({ severity: "warning" });
  });

  it("leaves mail, phone and relative links alone", () => {
    expect(linkFindings("mailto:help@example.com", "help@example.com")).toEqual([]);
    expect(linkFindings("tel:+15555550100", "Call us")).toEqual([]);
    expect(linkFindings("/relative", "x")).toEqual([]);
  });

  it("notes bare IPs, text before @ and punycode", () => {
    expect(titles(linkFindings("http://198.51.100.7/a", "Open"))).toEqual(["Link goes to a bare IP address"]);
    expect(titles(linkFindings("https://example.com@evil.test/", "Open"))).toEqual(["Link has text before @ in the address"]);
    expect(titles(linkFindings("https://xn--exmple-cua.test/", "Open"))).toEqual(["Link uses a punycode (xn--) domain"]);
  });

  it("reads the host a link's text claims", () => {
    expect(claimedHost("https://www.example.com/login")).toBe("www.example.com");
    expect(claimedHost("hxxps://example[.]com")).toBe("example.com");
    expect(claimedHost("Sign in")).toBeNull();
  });
});

describe("collectLinks", () => {
  it("merges HTML and plain-text links without duplicates", () => {
    const html = [readHtml('<a href="https://example.com/a">Go</a><a href="https://example.com/a">Go</a><a href="#top">Top</a>')];
    const links = collectLinks({ text: ["See https://example.com/a and https://example.net/b."] }, html);
    expect(links.map((l) => [l.source, l.href])).toEqual([
      ["html", "https://example.com/a"],
      ["text", "https://example.com/a"],
      ["text", "https://example.net/b"],
    ]);
  });
});

describe("classifyAttachment", () => {
  const classify = (filename: string, content: Uint8Array, contentType = "application/octet-stream") =>
    classifyAttachment({ filename, contentType, bytes: content as Uint8Array<ArrayBuffer> });

  it.each([
    ["setup.exe", "A program or script (.exe)"],
    ["run.js", "A program or script (.js)"],
    ["Invoice.LNK", "A Windows shortcut (.lnk)"],
    ["disk.iso", "A disk image (.iso)"],
    ["statement.htm", "A web page (.htm)"],
    ["budget.xlsm", "An Office document with macros (.xlsm)"],
    ["files.zip", "An archive (.zip)"],
  ])("flags %s as risky", (name, title) => {
    expect(titles(classify(name, ascii("hello")).findings)).toContain(title);
  });

  it("is critical for programs and warns for archives", () => {
    expect(classify("a.exe", ascii("x")).findings[0]?.severity).toBe("critical");
    expect(classify("a.zip", bytes(0x50, 0x4b, 0x03, 0x04)).findings.map((f) => f.severity)).toEqual(["warning"]);
  });

  it("flags content that doesn't match the name", () => {
    const pe = classify("invoice.pdf", bytes(0x4d, 0x5a, 0x90, 0));
    expect(pe.sniffed).toBe("Windows executable (PE)");
    expect(pe.findings[0]).toMatchObject({ severity: "critical", title: "Content doesn't match the .pdf name" });
    expect(classify("photo.jpg", ascii("%PDF-1.7")).findings[0]).toMatchObject({ severity: "warning", title: "Content doesn't match the .jpg name" });
  });

  it("accepts matching content, and Office files that are really ZIPs", () => {
    expect(classify("report.pdf", ascii("%PDF-1.7")).findings).toEqual([]);
    expect(classify("report.docx", bytes(0x50, 0x4b, 0x03, 0x04)).findings).toEqual([]);
    expect(classify("notes.txt", ascii("hello")).findings).toEqual([]);
  });

  it("flags names that hide their real type", () => {
    expect(titles(classify("invoice.pdf.exe", ascii("x")).findings)).toContain("File name hides its real type");
    expect(titles(classify("photo‮gpj.exe", ascii("x")).findings)).toContain("File name contains hidden direction characters");
  });

  it("flags an unnamed HTML part", () => {
    expect(classify("(no name)", ascii("<form>"), "text/html").findings[0]?.title).toBe("A web page");
  });
});

describe("sha256Hex", () => {
  it("hashes bytes", async () => {
    expect(await sha256Hex(ascii("abc"))).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });
});

const MESSAGE = [
  "Received: from mail.example.net (mail.example.net [192.0.2.10]) by mx.example.org; Tue, 08 Oct 2024 10:00:05 +0000",
  "Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=example.net; dkim=none; dmarc=fail header.from=example.com",
  'From: "Payroll" <payroll@example.com>',
  "Reply-To: desk@example.net",
  "Subject: Confirm at https://example-payroll.test now",
  "Date: Tue, 08 Oct 2024 10:00:00 +0000",
  "Message-ID: <1@example.net>",
  "Content-Type: multipart/mixed; boundary=b",
  "",
  "--b",
  "Content-Type: text/html",
  "",
  '<a href="https://example-payroll.test/confirm">https://www.example.com/payroll</a> or <a href="javascript:go()">here</a>',
  "--b",
  "Content-Type: application/octet-stream",
  'Content-Disposition: attachment; filename="payslip.pdf.exe"',
  "Content-Transfer-Encoding: base64",
  "",
  "TVqQAA==",
  "--b--",
].join("\n");

async function analyse(text = MESSAGE) {
  const msg = parseMime(text);
  const html = msg.html.map(readHtml);
  const headers = msg.headers ? analyzeHeaders(msg.headers) : null;
  const links = collectLinks(msg, html);
  const attachments = msg.attachments.map(reportAttachment);
  const hashes = await Promise.all(msg.attachments.map((a) => sha256Hex(a.bytes)));
  const indicators = triageIndicators(msg, html, links, headers, hashes);
  return { msg, headers, links, attachments, hashes, indicators, flags: triageFlags(headers, links, attachments) };
}

describe("triage", () => {
  it("summarises the strongest red flags from headers, links and attachments", async () => {
    const { flags } = await analyse();
    const t = titles(flags);
    expect(flags[0]?.severity).toBe("critical");
    expect(t).toContain("SPF failed");
    expect(t).toContain("Link text shows a different site");
    expect(t).toContain("Link uses a javascript: address");
    expect(t).toContain("payslip.pdf.exe: A program or script (.exe)");
    expect(t).toContain("payslip.pdf.exe: File name hides its real type");
    expect(flags.every((f) => f.severity !== "info")).toBe(true);
    expect(flags.length).toBeLessThanOrEqual(8);
  });

  it("counts repeated link problems once", () => {
    const links = collectLinks({ text: [] }, [readHtml('<a href="javascript:a()">1</a><a href="javascript:b()">2</a>')]);
    expect(titles(triageFlags(null, links, []))).toEqual(["Link uses a javascript: address (2 links)"]);
  });

  it("has nothing to say about a plain message, and never calls it safe", () => {
    expect(triageFlags(null, [], [])).toEqual([]);
    expect(NO_FLAGS).toMatch(/doesn't make it safe/);
  });

  it("gathers indicators from links, sender, hops and attachment hashes, de-duplicated", async () => {
    const { indicators, hashes } = await analyse();
    const values = indicators.map((i) => i.value);
    expect(values).toContain("https://example-payroll.test/confirm");
    expect(values).toContain("payroll@example.com");
    expect(values).toContain("desk@example.net");
    expect(values).toContain("example.net");
    expect(values).toContain("192.0.2.10");
    expect(values).toContain(hashes[0]);
    expect(new Set(values).size).toBe(values.length);
  });

  it("writes a defanged ticket note with verdicts", async () => {
    const a = await analyse();
    const url = a.indicators.find((i) => i.kind === "url")!;
    const verdicts = new Map([[`url:${url.value}`, { verdict: "listed" as const, listedBy: ["URLhaus"] }]]);
    const note = ticketNote({ ...a, verdicts, now: Date.UTC(2026, 9, 20, 12) });
    expect(note).toContain("Subject: Confirm at hxxps://example-payroll[.]test now");
    expect(note).toContain('From: "Payroll" <payroll@example[.]com>');
    expect(note).toContain("Reply-To: <desk@example[.]net>");
    expect(note).toContain("Authentication: SPF fail (example[.]net), DKIM none, DMARC fail (example[.]com)");
    expect(note).toContain("- Red flag: SPF failed");
    expect(note).toContain("- payslip[.]pdf[.]exe (application/octet-stream, 4 B, content: Windows executable (PE))");
    expect(note).toContain(`    SHA-256: ${a.hashes[0]}`);
    expect(note).toContain("- hxxps://example-payroll[.]test/confirm [listed by URLhaus]");
    expect(note).toContain("- 192[.]0[.]2[.]10");
    expect(note).toContain("Analysed 2026-10-20 12:00:00 UTC in the browser");
    // Nothing clickable survives.
    expect(note).not.toMatch(/https?:\/\//);
    expect(note).not.toMatch(/\b[a-z0-9-]+\.(com|net|org|test)\b/);
  });

  it("writes a ticket note for a message without headers or attachments", () => {
    const note = ticketNote({ headers: null, flags: [], attachments: [], hashes: [], indicators: [], verdicts: new Map() });
    expect(note).toContain("Subject: (none)");
    expect(note).toContain("Authentication: no results in the headers");
    expect(note).toContain("- None obvious. That doesn't make it safe.");
  });
});

describe("hand-off from Lookup", () => {
  it("holds one message in memory until cleared", () => {
    handOffMessage("From: a@example.com\n\nhi");
    expect(peekHandOff()).toBe("From: a@example.com\n\nhi");
    clearHandOff();
    expect(peekHandOff()).toBeNull();
  });
});
