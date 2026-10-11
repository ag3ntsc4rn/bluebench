import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { LookupPage } from "./LookupPage";

const render = (value: string) => renderToString(<LookupPage initialValue={value} />);
// React escapes text and inserts <!-- --> between adjacent text nodes; strip both for matching.
const text = (value: string) =>
  render(value)
    .replace(/<!-- -->/g, "")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");

describe("LookupPage", () => {
  it("shows no tool for empty input", () => {
    const html = render("");
    expect(html).not.toContain("Detected:");
    expect(html).toContain("Nothing is sent unless you choose Check reputation, and nothing is stored.");
  });

  it("says when it can't recognise input", () => {
    expect(text("hello there")).toContain("Couldn't recognise this.");
  });

  it("routes an IP to the indicator panel with its range", () => {
    const html = text("10[.]0[.]0[.]1");
    expect(html).toMatch(/aria-pressed="true"[^>]*>IPv4</);
    expect(html).toContain("Private (RFC 1918)");
    expect(html).toContain("Defanged input was refanged");
  });

  it("routes a JWT to the decoder", () => {
    const html = text("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.");
    expect(html).toContain('Algorithm is "none"');
    expect(html).toContain("Red flag");
  });

  it("routes base64 and offers to analyse decoded content", () => {
    const html = text(btoa("https://evil.example/login"));
    expect(html).toContain("https://evil.example/login");
    expect(html).toContain("Analyse decoded text (URL)");
  });

  it("routes URLs and URL-encoded text", () => {
    expect(text("http://paypal.com@198.51.100.7/")).toContain("Text before @ in the address");
    expect(text("%3Cscript%3E")).toContain("<script>");
  });

  it("routes email headers to the analyzer", () => {
    const html = text(
      "From: a@x.com\nReply-To: b@y.com\nSubject: hi\nAuthentication-Results: mx; spf=pass smtp.mailfrom=x.com; dkim=pass header.d=x.com; dmarc=pass header.from=x.com\nMessage-ID: <1@x.com>",
    );
    expect(html).toContain("Replies go somewhere else");
    expect(html).toContain("Hop path");
    expect(html.match(/>Pass</g)).toHaveLength(3);
  });

  it("has an Analyse button, disabled until there is input", () => {
    const analyse = (value: string) => /<button([^>]*)>Analyse<\/button>/.exec(render(value))![1];
    expect(analyse("")).toContain('disabled=""');
    expect(analyse("8.8.8.8")).not.toContain('disabled=""');
  });

  it("labels the return key Go for one-line input and Enter for multi-line", () => {
    expect(render("8.8.8.8")).toContain('enterKeyHint="go"');
    expect(render("From: a@x.com\nTo: b@y.com\nSubject: s")).toContain('enterKeyHint="enter"');
  });

  it("never uses inline style attributes (CSP forbids them)", () => {
    const html = render("Received: from a by b; Tue, 08 Oct 2024 10:00:00 +0000\nFrom: a@x.com\nSubject: s");
    expect(html).not.toMatch(/\sstyle="/);
  });
});
