/** Shared HTTP and Shopify session boundary; no authorization or refund dependencies. */
import type { IncomingMessage, ServerResponse } from "node:http";
import { normalizeShopDomain } from "./admin.js";
import { SessionTokenError, verifySessionToken } from "./session-token.js";

export interface SessionServerDeps {
  clientId: string;
  clientSecret: string;
  allowedShops: string[];
  now?: () => Date;
}

const MAX_BODY = 64 * 1024;

export async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new Error("body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

export function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, {
    "content-type": "application/json",
    // Admin UI extensions call from a Shopify-hosted origin with a bearer
    // token, not cookies, so a wildcard origin grants nothing extra.
    "access-control-allow-origin": "*",
  });
  res.end(JSON.stringify(body));
}

export function createSessionAuthenticator(deps: SessionServerDeps) {
  const allowed = new Set(deps.allowedShops.map(normalizeShopDomain));

  /** Verifies the session token and shop; on failure sends the response and returns null. */
  function authenticate(req: IncomingMessage, res: ServerResponse): { shop: string; userId?: string; token: string } | null {
    const auth = req.headers.authorization ?? "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    let shop: string;
    let userId: string | undefined;
    try {
      const s = verifySessionToken(token, {
        clientId: deps.clientId,
        clientSecret: deps.clientSecret,
        ...(deps.now ? { now: deps.now() } : {}),
      });
      shop = s.shop;
      userId = s.userId;
    } catch (err) {
      send(res, 401, { error: err instanceof SessionTokenError ? err.message : "unauthorized" });
      return null;
    }
    if (!allowed.has(shop)) {
      send(res, 403, { error: "shop not allowed" });
      return null;
    }
    return { shop, token, ...(userId !== undefined ? { userId } : {}) };
  }

  return authenticate;
}

export function preflight(res: ServerResponse): void {
  res.writeHead(204, {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "authorization, content-type",
    "access-control-max-age": "600",
  });
  res.end();
}
