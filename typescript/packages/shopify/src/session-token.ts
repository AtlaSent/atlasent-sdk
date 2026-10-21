/**
 * Verifies the session token Shopify attaches to requests from an embedded
 * app or admin UI extension: an HS256 JWT signed with the app's client secret.
 *
 * Checked: alg, signature, `aud` (the app's client id), `exp`/`nbf` with a
 * small clock skew, and that `iss` and `dest` name the same shop.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { normalizeShopDomain } from "./admin.js";

export interface SessionTokenClaims {
  iss: string;
  dest: string;
  aud: string;
  sub?: string;
  exp: number;
  nbf: number;
  iat?: number;
  jti?: string;
  sid?: string;
}

export interface VerifiedSession {
  shop: string;
  /** Shopify staff user id; absent for some non-user tokens. */
  userId?: string;
  claims: SessionTokenClaims;
}

export class SessionTokenError extends Error {
  override name = "SessionTokenError";
}

const b64url = (s: string) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");

export function verifySessionToken(
  token: string,
  opts: { clientId: string; clientSecret: string; now?: Date; skewSeconds?: number },
): VerifiedSession {
  const parts = token.split(".");
  if (parts.length !== 3) throw new SessionTokenError("malformed token");
  const [h, p, s] = parts as [string, string, string];

  let header: { alg?: string; typ?: string };
  let claims: SessionTokenClaims;
  try {
    header = JSON.parse(b64url(h).toString("utf8"));
    claims = JSON.parse(b64url(p).toString("utf8"));
  } catch {
    throw new SessionTokenError("malformed token");
  }
  if (header.alg !== "HS256") throw new SessionTokenError("unexpected alg");

  const expected = createHmac("sha256", opts.clientSecret).update(`${h}.${p}`).digest();
  const presented = b64url(s);
  if (presented.length !== expected.length || !timingSafeEqual(presented, expected)) {
    throw new SessionTokenError("bad signature");
  }

  const nowS = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  const skew = opts.skewSeconds ?? 5;
  if (claims.aud !== opts.clientId) throw new SessionTokenError("wrong audience");
  if (typeof claims.exp !== "number" || nowS > claims.exp + skew) throw new SessionTokenError("expired");
  if (typeof claims.nbf !== "number" || nowS + skew < claims.nbf) throw new SessionTokenError("not yet valid");

  let destShop: string;
  let issShop: string;
  try {
    destShop = normalizeShopDomain(new URL(claims.dest).host);
    issShop = normalizeShopDomain(new URL(claims.iss).host);
  } catch {
    throw new SessionTokenError("bad iss/dest");
  }
  if (destShop !== issShop) throw new SessionTokenError("iss and dest name different shops");

  return { shop: destShop, ...(typeof claims.sub === "string" ? { userId: claims.sub } : {}), claims };
}

/** Test helper and documentation of the format: sign claims the way Shopify does. */
export function signSessionToken(claims: SessionTokenClaims, clientSecret: string): string {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const h = enc({ alg: "HS256", typ: "JWT" });
  const p = enc(claims);
  const s = createHmac("sha256", clientSecret).update(`${h}.${p}`).digest("base64url");
  return `${h}.${p}.${s}`;
}
