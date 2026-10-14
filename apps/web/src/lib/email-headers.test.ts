import { describe, expect, it } from "vitest";
import {
  analyzeHeaders,
  decodeEncodedWords,
  parseAuthResults,
  parseHeaderFields,
  parseMailbox,
  parseReceived,
} from "./email-headers";

const LEGIT = `Delivered-To: me@example.org
Received: by 2002:a05:6a10:1234 with SMTP id x; Tue, 8 Oct 2024 10:00:09 -0700 (PDT)
Received: from mail.example.com (mail.example.com. [192.0.2.10])
        by mx.example.org with ESMTPS id abc123
        for <me@example.org>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Oct 2024 10:00:05 -0700 (PDT)
Received: from [10.0.0.5] (internal.example.com [10.0.0.5])
        by mail.example.com (Postfix) with ESMTPSA id 99;
        Tue, 08 Oct 2024 17:00:00 +0000
Authentication-Results: mx.example.org;
       dkim=pass header.i=@example.com header.s=s1 header.b=AbCd;
       spf=pass (example.org: domain of alice@example.com designates 192.0.2.10 as permitted sender) smtp.mailfrom=alice@example.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
Return-Path: <alice@example.com>
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=s1;
        h=from:to:subject; bh=abc=; b=def=
From: "Alice Example" <alice@example.com>
To: me@example.org
Subject: =?UTF-8?B?SGVsbG8g8J+Riw==?=
Date: Tue, 08 Oct 2024 09:59:58 -0700
Message-ID: <abc@mail.example.com>

Hi there`;

const PHISH = `Received: from mx.victim.org by inbox.victim.org; Tue, 08 Oct 2024 09:00:00 +0000
Received: from evil-host.example.net (unknown [198.51.100.66])
        by mx.victim.org with ESMTP; Tue, 08 Oct 2024 10:00:00 +0000
Authentication-Results: mx.victim.org; spf=fail smtp.mailfrom=bank.example; dkim=none; dmarc=fail header.from=bank.example
From: "support@bank.example" <security@bank-alerts.example.net>
From: support@bank.example
Reply-To: help@collector.example.com
Return-Path: <bounce@mailer.example.org>
Subject: Urgent: verify your account`;

describe("parseHeaderFields", () => {
  it("unfolds continuation lines and stops at the body", () => {
    const fields = parseHeaderFields("Subject: a\n  b\nFrom: x@y.com\n\nNot-A-Header: body");
    expect(fields).toEqual([
      { name: "Subject", value: "a b" },
      { name: "From", value: "x@y.com" },
    ]);
  });

  it("handles CRLF and leading blank lines", () => {
    expect(parseHeaderFields("\r\nA: 1\r\nB: 2\r\n")).toHaveLength(2);
  });
});

describe("decodeEncodedWords", () => {
  it("decodes B and Q encodings and joins adjacent words", () => {
    expect(decodeEncodedWords("=?UTF-8?B?SGVsbG8g8J+Riw==?=")).toBe("Hello 👋");
    expect(decodeEncodedWords("=?iso-8859-1?Q?Caf=E9_ouvert?=")).toBe("Café ouvert");
    expect(decodeEncodedWords("=?UTF-8?Q?a?= =?UTF-8?Q?b?= c")).toBe("ab c");
  });

  it("leaves malformed or unknown charsets alone", () => {
    expect(decodeEncodedWords("=?x-unknown?B?SGk=?=")).toBe("=?x-unknown?B?SGk=?=");
    expect(decodeEncodedWords("plain")).toBe("plain");
  });
});

describe("parseMailbox", () => {
  it("parses display names and bare addresses", () => {
    expect(parseMailbox('"Alice A." <Alice@Example.com>')).toEqual({ display: "Alice A.", address: "alice@example.com", domain: "example.com" });
    expect(parseMailbox("bob@example.com")).toEqual({ display: "", address: "bob@example.com", domain: "example.com" });
    expect(parseMailbox("<>")).toBeNull();
  });
});

describe("parseReceived", () => {
  it("extracts from, by, with, IP and date", () => {
    const hop = parseReceived(
      "from mail.example.com (mail.example.com. [192.0.2.10]) by mx.example.org with ESMTPS id x; Tue, 08 Oct 2024 10:00:05 -0700 (PDT)",
    );
    expect(hop).toMatchObject({ from: "mail.example.com", by: "mx.example.org", with: "ESMTPS", ip: "192.0.2.10" });
    expect(hop.at).toBe(Date.UTC(2024, 9, 8, 17, 0, 5));
    expect(hop.atDisplay).toBe("2024-10-08 17:00:05 UTC");
  });

  it("handles IPv6 literals and missing dates", () => {
    expect(parseReceived("from x ([IPv6:2001:db8::1]) by y")).toMatchObject({ ip: "2001:db8::1", by: "y" });
    expect(parseReceived("from x by y").at).toBeUndefined();
  });
});

describe("parseAuthResults", () => {
  it("parses methods, results, domains and selectors, ignoring comments", () => {
    expect(
      parseAuthResults(
        'mx.google.com; dkim=pass header.i=@a.com header.s=sel header.b="x"; spf=softfail (google.com: x) smtp.mailfrom=bounce@b.com; dmarc=fail (p=NONE) header.from=a.com',
      ),
    ).toEqual([
      { method: "dkim", result: "pass", domain: "a.com", selector: "sel", source: "Authentication-Results" },
      { method: "spf", result: "softfail", domain: "b.com", source: "Authentication-Results" },
      { method: "dmarc", result: "fail", domain: "a.com", source: "Authentication-Results" },
    ]);
  });
});

describe("analyzeHeaders", () => {
  it("summarises a legitimate message with no red flags", () => {
    const a = analyzeHeaders(LEGIT);
    expect(a.subject).toBe("Hello 👋");
    expect(a.from).toMatchObject({ address: "alice@example.com", display: "Alice Example" });
    expect(a.auth.map((r) => `${r.method}=${r.result}`)).toEqual(["spf=pass", "dkim=pass", "dmarc=pass"]);
    expect(a.dkimSignatures).toEqual([{ domain: "example.com", selector: "s1" }]);
    expect(a.hops.map((h) => h.by)).toEqual(["mail.example.com", "mx.example.org", "2002:a05:6a10:1234"]);
    expect(a.hops.map((h) => h.delay)).toEqual([undefined, 5, 4]);
    expect(a.totalDelay).toBe("9 s");
    expect(a.findings).toEqual([]);
  });

  it("treats tenants of a shared hosting platform as different senders (#30)", () => {
    const headers = (from: string, replyTo: string) =>
      [
        "Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=" + from.split("@")[1] + "; dkim=pass header.d=" + from.split("@")[1] + "; dmarc=pass header.from=" + from.split("@")[1],
        `From: ${from}`,
        `Reply-To: ${replyTo}`,
        "Subject: hello",
        "Message-ID: <1@x>",
      ].join("\n");
    const titles = (from: string, replyTo: string) => analyzeHeaders(headers(from, replyTo)).findings.map((f) => f.title);
    expect(titles("alice@victim.github.io", "attacker@evil.github.io")).toContain("Replies go somewhere else");
    expect(titles("it@contoso.onmicrosoft.com", "help@attacker.onmicrosoft.com")).toContain("Replies go somewhere else");
    // Same tenant, different subdomain: still the same organisation.
    expect(titles("alice@victim.github.io", "bob@www.victim.github.io")).not.toContain("Replies go somewhere else");
  });

    it("flags a spoofed message", () => {
    const a = analyzeHeaders(PHISH);
    const titles = a.findings.map((f) => f.title);
    expect(titles).toEqual(
      expect.arrayContaining([
        "More than one From header",
        "SPF failed",
        "Not DKIM-signed",
        "DMARC failed",
        "Replies go somewhere else",
        "Bounce address on another domain",
        "Display name shows a different address",
        "Hop times go backwards",
        "No Message-ID",
      ]),
    );
    expect(a.findings[0]!.severity).toBe("critical");
    expect(a.findings.at(-1)!.severity).toBe("info");
  });

  it("falls back to Received-SPF and says when auth results are missing", () => {
    const withSpf = analyzeHeaders(
      "From: a@x.com\nReceived-SPF: softfail (domain of transitioning a@x.com) envelope-from=<a@x.com>;\nSubject: hi\nMessage-ID: <1@x.com>",
    );
    expect(withSpf.auth).toEqual([{ method: "spf", result: "softfail", domain: "x.com", source: "Received-SPF" }]);
    expect(withSpf.findings.map((f) => f.title)).toContain("SPF soft fail");

    const bare = analyzeHeaders("From: a@x.com\nTo: b@y.com\nSubject: hi\nMessage-ID: <1@x.com>");
    expect(bare.findings.map((f) => f.title)).toEqual(["No authentication results"]);
  });
});
