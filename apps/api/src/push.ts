import { isPushEndpoint } from "@bluebench/shared";

/**
 * Web Push with WebCrypto only: VAPID (RFC 8292) to identify us to the push service, and
 * aes128gcm payload encryption (RFC 8291) so the push service can't read the alert.
 */

const enc = new TextEncoder();

export function b64urlEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(text: string): Uint8Array {
  // Trim padding with a loop: /=+$/ backtracks quadratically on long runs of "=" (CodeQL js/polynomial-redos).
  let end = text.length;
  while (end > 0 && text[end - 1] === "=") end--;
  const b64 = text.slice(0, end).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

async function hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, bytes: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, bytes * 8));
}

/** Records are a single block; 4096 is the conventional record size. */
const RECORD_SIZE = 4096;

/**
 * Encrypt a payload for one subscription (RFC 8291, aes128gcm content coding).
 * Returns the request body: salt ‖ record size ‖ key id length ‖ our ephemeral public key ‖ ciphertext.
 */
export async function encryptPayload(
  payload: Uint8Array,
  sub: { p256dh: string; auth: string },
  // Injectable so tests can pin the randomness.
  rand: { salt?: Uint8Array; keys?: CryptoKeyPair } = {},
): Promise<Uint8Array> {
  const uaPublic = b64urlDecode(sub.p256dh);
  const authSecret = b64urlDecode(sub.auth);
  const salt = rand.salt ?? crypto.getRandomValues(new Uint8Array(16));
  const local = rand.keys ?? ((await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair);
  const asPublic = new Uint8Array((await crypto.subtle.exportKey("raw", local.publicKey)) as ArrayBuffer);

  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  // workers-types call the key `$public` (an IDL artifact); the runtime reads `public`, as in browsers.
  const ecdh = { name: "ECDH", public: uaKey } as unknown as SubtleCryptoDeriveKeyAlgorithm;
  const ecdhSecret = new Uint8Array(await crypto.subtle.deriveBits(ecdh, local.privateKey, 256));

  const keyInfo = concat(enc.encode("WebPush: info\0"), uaPublic, asPublic);
  const ikm = await hkdf(authSecret, ecdhSecret, keyInfo, 32);
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);

  // One record: the payload followed by the 0x02 "last record" delimiter, no padding.
  const aesKey = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, concat(payload, new Uint8Array([2]))));

  const header = new Uint8Array(21);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, RECORD_SIZE);
  header[20] = asPublic.length;
  return concat(header, asPublic, ciphertext);
}

export interface VapidKeys {
  /** base64url 65-byte uncompressed P-256 point. */
  publicKey: string;
  /** base64url 32-byte private scalar. */
  privateKey: string;
  /** Contact for push services, e.g. mailto:security@bluebench.dev. */
  subject: string;
}

function importVapidKey(keys: VapidKeys): Promise<CryptoKey> {
  const pub = b64urlDecode(keys.publicKey);
  if (pub.length !== 65 || pub[0] !== 4) throw new Error("VAPID public key must be an uncompressed P-256 point");
  return crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: b64urlEncode(pub.slice(1, 33)), y: b64urlEncode(pub.slice(33)), d: keys.privateKey, ext: false },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
}

/** The `Authorization: vapid t=…, k=…` header for a push service origin. Valid for 12 hours. */
export async function vapidAuthorization(endpoint: string, keys: VapidKeys, now = Date.now()): Promise<string> {
  const header = b64urlEncode(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = b64urlEncode(
    enc.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(now / 1000) + 12 * 3600, sub: keys.subject })),
  );
  const unsigned = `${header}.${claims}`;
  // WebCrypto's ECDSA signature is already the raw r ‖ s form JWS wants.
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, await importVapidKey(keys), enc.encode(unsigned));
  return `vapid t=${unsigned}.${b64urlEncode(new Uint8Array(sig))}, k=${keys.publicKey}`;
}

export interface PushMessage {
  title: string;
  body: string;
  /** Same-origin path the notification opens. */
  url: string;
  /** Replaces an earlier notification with the same tag. */
  tag?: string;
}

/** "gone" = the subscription has expired or was revoked; delete it. */
export type PushResult = "sent" | "gone" | "failed";

/** Send one push. Refuses endpoints outside the known push services (they're user-supplied URLs). */
export async function sendPush(sub: { endpoint: string; p256dh: string; auth: string }, msg: PushMessage, keys: VapidKeys): Promise<PushResult> {
  if (!isPushEndpoint(sub.endpoint)) return "gone";
  try {
    const body = await encryptPayload(enc.encode(JSON.stringify(msg)), sub);
    const res = await fetch(sub.endpoint, {
      method: "POST",
      headers: {
        authorization: await vapidAuthorization(sub.endpoint, keys),
        "content-encoding": "aes128gcm",
        "content-type": "application/octet-stream",
        ttl: String(24 * 3600),
        urgency: "normal",
      },
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(5000),
    });
    if (res.status === 404 || res.status === 410) return "gone";
    return res.ok ? "sent" : "failed";
  } catch {
    return "failed";
  }
}
