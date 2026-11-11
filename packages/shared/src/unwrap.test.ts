import { describe, expect, it } from "vitest";
import { detect } from "./detect.ts";
import { extractIndicators } from "./extract.ts";
import { unwrapLink } from "./unwrap.ts";

const INNER = "https://evil.example.net/login?next=/inbox&id=42";
const SAFELINKS = `https://nam12.safelinks.protection.outlook.com/?url=${encodeURIComponent(INNER)}&data=05%7C02%7Cuser%40contoso.com%7Cabc&sdata=xyz%3D&reserved=0`;
// Proofpoint v2: percent-encoding with "-" for "%" and "_" for "/".
const PROOFPOINT_V2 = `https://urldefense.proofpoint.com/v2/url?u=${encodeURIComponent(INNER).replace(/%/g, "-").replace(/\//g, "_")}&d=DwMFaQ&c=abc&r=def&m=ghi&s=jkl&e=`;
// Proofpoint v3: "?", "=" and "&" each replaced by "*", then "**B" for the 3-character run "=42";
// the missing characters, "?=&=42", are "Pz0mPTQy" in URL-safe base64.
const PROOFPOINT_V3 = "https://urldefense.com/v3/__https://evil.example.net/login*next*/inbox*id**B__;Pz0mPTQy!!ABCdef!ghiJKL$";

describe("unwrapLink", () => {
  it("unwraps Microsoft Safe Links, including GCC High", () => {
    expect(unwrapLink(SAFELINKS)).toEqual({ wrapper: "Microsoft Safe Links", url: INNER, host: "evil.example.net" });
    expect(unwrapLink(SAFELINKS.replace("nam12.safelinks.protection.outlook.com", "gcc02.safelinks.protection.office365.us"))?.url).toBe(INNER);
  });

  it("unwraps Proofpoint URL Defense v1, v2 and v3", () => {
    expect(unwrapLink(`https://urldefense.proofpoint.com/v1/url?u=${encodeURIComponent(INNER)}&k=abc`)?.url).toBe(INNER);
    expect(unwrapLink(PROOFPOINT_V2)).toEqual({ wrapper: "Proofpoint URL Defense", url: INNER, host: "evil.example.net" });
    expect(unwrapLink(PROOFPOINT_V3)).toEqual({ wrapper: "Proofpoint URL Defense", url: INNER, host: "evil.example.net" });
    expect(unwrapLink("https://urldefense.com/v3/__https://example.org/plain__;!!ABC$")?.url).toBe("https://example.org/plain");
  });

  it("recovers only the domain from Mimecast", () => {
    expect(unwrapLink("https://protect-eu.mimecast.com/s/AbCdEfGhIjK?domain=evil.example.net")).toEqual({
      wrapper: "Mimecast",
      url: null,
      host: "evil.example.net",
    });
    expect(unwrapLink("https://protect-eu.mimecast.com/s/AbCdEfGhIjK")).toBeNull();
  });

  it("peels nested wrappers and names the outer one", () => {
    const nested = `https://eur01.safelinks.protection.outlook.com/?url=${encodeURIComponent(PROOFPOINT_V2)}&data=x`;
    expect(unwrapLink(nested)).toEqual({ wrapper: "Microsoft Safe Links", url: INNER, host: "evil.example.net" });
  });

  it("ignores ordinary links, broken wrappers and non-web schemes", () => {
    expect(unwrapLink("https://example.com/?url=https://evil.example.net/")).toBeNull();
    expect(unwrapLink("https://nam12.safelinks.protection.outlook.com/?data=x")).toBeNull();
    expect(unwrapLink(`https://nam12.safelinks.protection.outlook.com/?url=${encodeURIComponent("javascript:alert(1)")}`)).toBeNull();
    expect(unwrapLink("https://urldefense.com/v3/__https://example.org/a*b__;!!ABC$")).toBeNull(); // missing replacement
    expect(unwrapLink("not a url")).toBeNull();
  });
});

describe("wrapped links in detection and extraction", () => {
  it("analyses the wrapped link on Lookup", () => {
    expect(detect(SAFELINKS)[0]).toEqual({ kind: "url", value: INNER, refanged: false, unwrapped: "Microsoft Safe Links" });
    expect(detect("https://protect-eu.mimecast.com/s/AbC?domain=evil.example.net")[0]).toEqual({
      kind: "domain",
      value: "evil.example.net",
      refanged: false,
      unwrapped: "Mimecast",
    });
  });

  it("extracts the wrapped link, not the wrapper", () => {
    expect(extractIndicators(`Clicked ${SAFELINKS} and ${PROOFPOINT_V3} at 10:02`)).toEqual([{ kind: "url", value: INNER }]);
  });
});
