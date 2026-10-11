import { base64ToBytes, tryParseJson } from "@bluebench/shared";
import { formatDuration, formatUtc, sortFindings, type Finding } from "./findings";

export interface JwtTimeClaim {
  claim: "exp" | "nbf" | "iat";
  label: string;
  /** Milliseconds since epoch. */
  at: number;
  display: string;
}

export interface DecodedJwt {
  header: unknown;
  payload: unknown;
  /** Payload as text when it isn't JSON (e.g. a JWE or nested token). */
  payloadText?: string;
  signature: string;
  times: JwtTimeClaim[];
  findings: Finding[];
}

function decodeSegment(segment: string): { json: unknown; text: string } | null {
  const bytes = base64ToBytes(segment);
  if (!bytes) return null;
  const text = new TextDecoder().decode(bytes);
  return { json: tryParseJson(text), text };
}

const TIME_LABELS = { exp: "Expires", nbf: "Not before", iat: "Issued" } as const;

/** Decode a JWT without verifying it. Verification needs the key, which we never ask for. */
export function decodeJwt(token: string, now = Date.now()): DecodedJwt | null {
  const [h = "", p = "", signature = ""] = token.trim().split(".");
  const header = decodeSegment(h);
  const payload = decodeSegment(p);
  if (!header || header.json === undefined || !payload) return null;

  const findings: Finding[] = [];
  const claims = (payload.json && typeof payload.json === "object" ? payload.json : {}) as Record<string, unknown>;
  const alg = (header.json as Record<string, unknown>).alg;

  if (typeof alg === "string" && alg.toLowerCase() === "none") {
    findings.push({
      severity: "critical",
      title: 'Algorithm is "none"',
      detail: "This token isn't signed. A server that accepts it lets anyone forge tokens.",
    });
  } else if (!signature) {
    findings.push({ severity: "warning", title: "No signature", detail: "The signature part is empty." });
  }

  const times: JwtTimeClaim[] = [];
  for (const claim of ["iat", "nbf", "exp"] as const) {
    const v = claims[claim];
    if (typeof v !== "number" || !Number.isFinite(v)) continue;
    const at = v * 1000;
    const rel = formatDuration((at - now) / 1000);
    const when = at > now ? `in ${rel}` : `${formatDuration((now - at) / 1000)} ago`;
    times.push({ claim, label: TIME_LABELS[claim], at, display: `${formatUtc(at)} (${when})` });
    if (claim === "exp" && at <= now) {
      findings.push({ severity: "warning", title: "Expired", detail: `Expired ${formatDuration((now - at) / 1000)} ago.` });
    }
    if (claim === "nbf" && at > now) {
      findings.push({ severity: "warning", title: "Not valid yet", detail: `Becomes valid in ${rel}.` });
    }
  }
  if (claims.exp === undefined && payload.json !== undefined) {
    findings.push({ severity: "info", title: "No expiry", detail: "Without an exp claim this token never expires on its own." });
  }

  findings.push({
    severity: "info",
    title: "Signature not verified",
    detail: "Decoding shows what the token claims. It doesn't prove who issued it.",
  });

  return {
    header: header.json,
    payload: payload.json,
    payloadText: payload.json === undefined ? payload.text : undefined,
    signature,
    times,
    findings: sortFindings(findings),
  };
}
