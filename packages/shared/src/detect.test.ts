import { describe, expect, it } from "vitest";
import { detect, looksLikeEmailHeaders, MAX_PASTE_LENGTH, refang, sniffFileType } from "./detect.ts";
import { normalizeDomain, orgDomain } from "./domain.ts";
import { base64ToBytes, bytesToText } from "./encoding.ts";

const kinds = (s: string) => detect(s).map((d) => d.kind);
const first = (s: string) => detect(s)[0];

const JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

const HEADERS = `Delivered-To: me@example.org
Received: from mail.example.com (mail.example.com [192.0.2.1])
        by mx.example.org with ESMTPS id abc; Tue, 08 Oct 2024 10:00:05 +0000
From: Alice <alice@example.com>
Subject: hello
Date: Tue, 08 Oct 2024 10:00:00 +0000

body text`;

describe("refang", () => {
  it("undoes common defanging", () => {
    expect(refang("hxxps[:]//evil[.]com/a")).toBe("https://evil.com/a");
    expect(refang("evil(.)com")).toBe("evil.com");
    expect(refang("bad[dot]example[.]org")).toBe("bad.example.org");
    expect(refang("user[@]evil[.]com")).toBe("user@evil.com");
    expect(refang("hXXp://x[.]io")).toBe("http://x.io");
  });

  it("leaves normal text alone", () => {
    expect(refang("https://example.com/[x]")).toBe("https://example.com/[x]");
  });
});

describe("detect", () => {
  it("returns nothing for empty, unrecognised or oversized input", () => {
    expect(detect("")).toEqual([]);
    expect(detect("   \n ")).toEqual([]);
    expect(detect("hello")).toEqual([]);
    expect(detect("just some words here")).toEqual([]);
    expect(detect("a".repeat(MAX_PASTE_LENGTH + 1))).toEqual([]);
  });

  it("detects IPv4 and IPv6", () => {
    expect(first(" 203.0.113.7 ")).toEqual({ kind: "ipv4", value: "203.0.113.7", refanged: false });
    expect(first("203[.]0[.]113[.]7")).toEqual({ kind: "ipv4", value: "203.0.113.7", refanged: true });
    expect(first("2001:DB8::0001")).toMatchObject({ kind: "ipv6", value: "2001:db8::1" });
    expect(first("[2001:db8::1]")).toMatchObject({ kind: "ipv6", value: "2001:db8::1" });
    expect(kinds("999.1.1.1")).not.toContain("ipv4");
  });

  it("detects domains, including IDNs and defanged ones", () => {
    expect(first("Example.COM.")).toMatchObject({ kind: "domain", value: "example.com" });
    expect(first("evil[.]example[.]co[.]uk")).toEqual({ kind: "domain", value: "evil.example.co.uk", refanged: true });
    expect(first("bücher.de")).toMatchObject({ kind: "domain", value: "xn--bcher-kva.de" });
    expect(kinds("localhost")).toEqual([]);
    expect(kinds("example.123")).toEqual([]);
  });

  it("detects URLs, with or without a scheme", () => {
    expect(first("https://Example.com/login?x=1")).toMatchObject({ kind: "url", value: "https://example.com/login?x=1" });
    expect(first("hxxp://evil[.]com/payload.exe")).toEqual({
      kind: "url",
      value: "http://evil.com/payload.exe",
      refanged: true,
    });
    expect(first("example.com/path")).toMatchObject({ kind: "url", value: "http://example.com/path" });
    expect(first("192.0.2.1:8080/x")).toMatchObject({ kind: "url", value: "http://192.0.2.1:8080/x" });
    expect(kinds("javascript://alert(1)")).not.toContain("url");
  });

  it("detects hashes by length", () => {
    expect(first("D41D8CD98F00B204E9800998ECF8427E")).toMatchObject({ kind: "md5", value: "d41d8cd98f00b204e9800998ecf8427e" });
    expect(first("da39a3ee5e6b4b0d3255bfef95601890afd80709")?.kind).toBe("sha1");
    expect(first("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")?.kind).toBe("sha256");
    expect(kinds("e3b0c44298fc1c149afbf4c8996fb924")).toEqual(["md5"]); // not also base64
  });

  it("detects email addresses", () => {
    expect(first("Alice@Example.COM")).toMatchObject({ kind: "email", value: "Alice@example.com" });
    expect(first("bob[@]evil[.]com")).toEqual({ kind: "email", value: "bob@evil.com", refanged: true });
    expect(kinds("a@b")).toEqual([]);
  });

  it("detects JWTs, including unsigned ones", () => {
    expect(kinds(JWT)).toEqual(["jwt"]);
    expect(kinds("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.")).toEqual(["jwt"]);
    expect(kinds("eyJmb28iOiJiYXIifQ.eyJzdWIiOiJ4In0.sig")).not.toContain("jwt"); // header has no alg
  });

  it("detects base64 that decodes to text or a known file type", () => {
    expect(first("aGVsbG8gd29ybGQ=")).toMatchObject({ kind: "base64", value: "aGVsbG8gd29ybGQ=" });
    expect(kinds("TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA==")).toEqual([
      "base64",
    ]);
    // PowerShell -EncodedCommand (UTF-16LE)
    expect(kinds("VwByAGkAdABlAC0ASABvAHMAdAAgACIAaABpACIA")).toEqual(["base64"]);
    expect(kinds("Password")).toEqual([]);
    expect(kinds("deadbeefcafe")).toEqual([]);
  });

  it("joins wrapped multi-line base64", () => {
    expect(detect("aGVsbG8g\nd29ybGQ=")).toEqual([{ kind: "base64", value: "aGVsbG8gd29ybGQ=", refanged: false }]);
  });

  it("detects URL-encoded text", () => {
    expect(kinds("%3Cscript%3Ealert(1)%3C%2Fscript%3E")).toEqual(["url-encoded"]);
  });

  it("detects raw email headers", () => {
    expect(kinds(HEADERS)).toEqual(["email-headers"]);
    expect(kinds("line one\nline two\nline three")).toEqual([]);
  });
});

describe("looksLikeEmailHeaders", () => {
  it("needs several recognised fields", () => {
    expect(looksLikeEmailHeaders(HEADERS)).toBe(true);
    expect(looksLikeEmailHeaders("Foo: 1\nBar: 2\nBaz: 3")).toBe(false);
    expect(looksLikeEmailHeaders("Subject: x\n\nFrom: y\nTo: z")).toBe(false); // only one field before the blank line
  });
});

describe("encoding helpers", () => {
  it("decodes standard and URL-safe base64 with or without padding", () => {
    expect(new TextDecoder().decode(base64ToBytes("aGk=")!)).toBe("hi");
    expect(new TextDecoder().decode(base64ToBytes("aGk")!)).toBe("hi");
    expect(base64ToBytes("-_8")).toEqual(new Uint8Array([0xfb, 0xff]));
    expect(base64ToBytes("a")).toBeNull();
    expect(base64ToBytes("a=b=")).toBeNull();
  });

  it("recognises UTF-16LE and rejects binary", () => {
    expect(bytesToText(new Uint8Array([0x68, 0, 0x69, 0]))).toEqual({ text: "hi", encoding: "UTF-16LE" });
    expect(bytesToText(new Uint8Array([0xff, 0xfe, 0x00, 0x01, 0x02]))).toBeNull();
  });

  it("sniffs file types", () => {
    expect(sniffFileType(new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]))).toBe("PDF document");
    expect(sniffFileType(new Uint8Array([1, 2, 3]))).toBeNull();
  });
});

describe("domains", () => {
  it("normalizes and validates hostnames", () => {
    expect(normalizeDomain("_dmarc.Example.com")).toBe("_dmarc.example.com");
    expect(normalizeDomain("-bad.com")).toBeNull();
    expect(normalizeDomain("a..com")).toBeNull();
    expect(normalizeDomain(`${"a".repeat(64)}.com`)).toBeNull();
  });

  it("approximates the organizational domain", () => {
    expect(orgDomain("mail.eu.example.com")).toBe("example.com");
    expect(orgDomain("bounce.shop.example.co.uk")).toBe("example.co.uk");
    expect(orgDomain("example.com")).toBe("example.com");
  });
});
