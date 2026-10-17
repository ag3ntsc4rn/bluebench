import { describe, expect, it } from "vitest";
import { isPushEndpoint } from "@bluebench/shared";
import { b64urlDecode, b64urlEncode, encryptPayload, vapidAuthorization } from "../src/push.ts";

// RFC 8291 section 5 (worked example).
const RFC = {
  plaintext: "When I grow up, I want to be a watermelon",
  authSecret: "BTBZMqHH6r4Tts7J_aSIgg",
  uaPublic: "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
  uaPrivate: "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94",
  asPublic: "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8",
  asPrivate: "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw",
  salt: "DGv6ra1nlYgDCS1FRnbzlw",
  body:
    "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN",
};

/** Import a P-256 key pair from the RFC's raw public point and private scalar. */
async function keyPair(pub: string, priv: string, alg: "ECDH" | "ECDSA"): Promise<CryptoKeyPair> {
  const p = b64urlDecode(pub);
  const jwk = { kty: "EC", crv: "P-256", x: b64urlEncode(p.slice(1, 33)), y: b64urlEncode(p.slice(33)) };
  const usages = alg === "ECDH" ? (["deriveBits"] as const) : (["sign"] as const);
  const privateKey = await crypto.subtle.importKey("jwk", { ...jwk, d: priv }, { name: alg, namedCurve: "P-256" }, true, [...usages]);
  const publicKey = await crypto.subtle.importKey("jwk", jwk, { name: alg, namedCurve: "P-256" }, true, alg === "ECDH" ? [] : ["verify"]);
  return { privateKey, publicKey };
}

describe("encryptPayload (RFC 8291 aes128gcm)", () => {
  it("matches the RFC's worked example byte for byte", async () => {
    const body = await encryptPayload(
      new TextEncoder().encode(RFC.plaintext),
      { p256dh: RFC.uaPublic, auth: RFC.authSecret },
      { salt: b64urlDecode(RFC.salt), keys: await keyPair(RFC.asPublic, RFC.asPrivate, "ECDH") },
    );
    expect(b64urlEncode(body)).toBe(RFC.body);
  });

  it("uses fresh randomness each time and lays out the header as the RFC says", async () => {
    const sub = { p256dh: RFC.uaPublic, auth: RFC.authSecret };
    const a = await encryptPayload(new TextEncoder().encode("hi"), sub);
    const b = await encryptPayload(new TextEncoder().encode("hi"), sub);
    expect(b64urlEncode(a)).not.toBe(b64urlEncode(b));
    expect(new DataView(a.buffer).getUint32(16)).toBe(4096); // record size
    expect(a[20]).toBe(65); // key id = our 65-byte public key
    expect(a.length).toBe(21 + 65 + 2 + 1 + 16); // header, key, payload, delimiter, GCM tag
  });
});

describe("b64url", () => {
  it("decodes with or without padding, and round-trips", () => {
    const bytes = Uint8Array.from([0xfb, 0xff, 0xbf, 0x00, 0x7e]);
    expect(b64urlEncode(bytes)).toBe("-_-_AH4");
    expect(b64urlDecode("-_-_AH4")).toEqual(bytes);
    expect(b64urlDecode("-_-_AH4=")).toEqual(bytes);
  });

  it("strips a long run of padding in linear time", () => {
    expect(b64urlDecode("AQ" + "=".repeat(100_000))).toEqual(Uint8Array.from([1]));
  });
});

describe("vapidAuthorization (RFC 8292)", () => {
  it("signs a JWT for the push service's origin that verifies with the public key", async () => {
    const keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const jwk = (await crypto.subtle.exportKey("jwk", keys.privateKey)) as JsonWebKey;
    const pub = new Uint8Array((await crypto.subtle.exportKey("raw", keys.publicKey)) as ArrayBuffer);
    const vapid = { publicKey: b64urlEncode(pub), privateKey: jwk.d!, subject: "mailto:security@bluebench.dev" };
    const now = Date.UTC(2026, 9, 11);

    const header = await vapidAuthorization("https://fcm.googleapis.com/fcm/send/abc", vapid, now);
    const m = /^vapid t=([\w-]+)\.([\w-]+)\.([\w-]+), k=([\w-]+)$/.exec(header);
    expect(m).not.toBeNull();
    const [, h, c, sig, k] = m!;
    expect(k).toBe(vapid.publicKey);
    expect(JSON.parse(new TextDecoder().decode(b64urlDecode(h!)))).toEqual({ typ: "JWT", alg: "ES256" });
    expect(JSON.parse(new TextDecoder().decode(b64urlDecode(c!)))).toEqual({
      aud: "https://fcm.googleapis.com",
      exp: now / 1000 + 12 * 3600,
      sub: "mailto:security@bluebench.dev",
    });
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      keys.publicKey,
      b64urlDecode(sig!),
      new TextEncoder().encode(`${h}.${c}`),
    );
    expect(ok).toBe(true);
  });
});

describe("isPushEndpoint", () => {
  it.each([
    "https://fcm.googleapis.com/fcm/send/abc:def",
    "https://updates.push.services.mozilla.com/wpush/v2/gAAAA",
    "https://web.push.apple.com/QGx",
    "https://wns2-par02p.notify.windows.com/w/?token=x",
  ])("accepts %s", (url) => expect(isPushEndpoint(url)).toBe(true));

  it.each([
    "http://fcm.googleapis.com/fcm/send/abc", // not https
    "https://fcm.googleapis.com:8443/fcm/send/abc", // odd port
    "https://evil.example/fcm.googleapis.com",
    "https://fcm.googleapis.com.evil.example/x",
    "https://user@fcm.googleapis.com/x",
    "https://169.254.169.254/latest/meta-data",
    "https://localhost/push",
    "not a url",
  ])("refuses %s", (url) => expect(isPushEndpoint(url)).toBe(false));
});
