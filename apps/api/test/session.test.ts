import { describe, expect, it } from "vitest";
import { signSession, verifySession, SESSION_TTL_SECONDS } from "../src/session.ts";

const SECRET = "s3cret";

describe("session tokens", () => {
  it("round-trips a signed token", async () => {
    const { token, session } = await signSession(SECRET);
    expect(await verifySession(SECRET, token)).toEqual(session);
  });

  it("rejects a token signed with another secret", async () => {
    const { token } = await signSession("other");
    expect(await verifySession(SECRET, token)).toBeNull();
  });

  it("rejects a tampered expiry", async () => {
    const { token, session } = await signSession(SECRET);
    const forged = token.replace(`.${session.exp}.`, `.${session.exp + 9999}.`);
    expect(await verifySession(SECRET, forged)).toBeNull();
  });

  it("rejects an expired token", async () => {
    const now = Date.now();
    const { token } = await signSession(SECRET, now);
    expect(await verifySession(SECRET, token, now + (SESSION_TTL_SECONDS + 1) * 1000)).toBeNull();
  });

  it.each([undefined, "", "garbage", "a.b.c", "x".repeat(200)])("rejects malformed %j", async (t) => {
    expect(await verifySession(SECRET, t)).toBeNull();
  });
});
