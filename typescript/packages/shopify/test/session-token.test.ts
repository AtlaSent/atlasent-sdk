import { describe, expect, it } from "vitest";
import { signSessionToken, verifySessionToken, type SessionTokenClaims } from "../src/session-token.js";

const CLIENT_ID = "client-123";
const SECRET = "shpss_secret";
const now = new Date("2026-10-20T12:00:00Z");
const t = Math.floor(now.getTime() / 1000);

const claims = (over: Partial<SessionTokenClaims> = {}): SessionTokenClaims => ({
  iss: "https://pinecone.myshopify.com/admin",
  dest: "https://pinecone.myshopify.com",
  aud: CLIENT_ID,
  sub: "42",
  exp: t + 60,
  nbf: t - 5,
  iat: t - 5,
  ...over,
});
const verify = (token: string) => verifySessionToken(token, { clientId: CLIENT_ID, clientSecret: SECRET, now });

describe("verifySessionToken", () => {
  it("accepts a valid token and returns shop and user", () => {
    expect(verify(signSessionToken(claims(), SECRET))).toMatchObject({ shop: "pinecone.myshopify.com", userId: "42" });
  });

  const bad: Array<[string, () => string, RegExp]> = [
    ["a token signed with another secret", () => signSessionToken(claims(), "other"), /bad signature/],
    ["another app's token", () => signSessionToken(claims({ aud: "other-app" }), SECRET), /wrong audience/],
    ["an expired token", () => signSessionToken(claims({ exp: t - 60 }), SECRET), /expired/],
    ["a not-yet-valid token", () => signSessionToken(claims({ nbf: t + 60 }), SECRET), /not yet valid/],
    ["iss and dest for different shops", () => signSessionToken(claims({ dest: "https://evil.myshopify.com" }), SECRET), /different shops/],
    ["a non-Shopify dest", () => signSessionToken(claims({ dest: "https://evil.example.com", iss: "https://evil.example.com/admin" }), SECRET), /bad iss\/dest/],
    ["garbage", () => "not.a.jwt", /malformed/],
    [
      "alg none",
      () => {
        const [, p] = signSessionToken(claims(), SECRET).split(".");
        return `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${p}.`;
      },
      /unexpected alg/,
    ],
    [
      "edited claims under the original signature",
      () => {
        const [h, , s] = signSessionToken(claims(), SECRET).split(".");
        return `${h}.${Buffer.from(JSON.stringify(claims({ sub: "1" }))).toString("base64url")}.${s}`;
      },
      /bad signature/,
    ],
  ];
  for (const [name, mk, why] of bad) it(`rejects ${name}`, () => expect(() => verify(mk())).toThrow(why));
});
