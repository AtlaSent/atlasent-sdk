/** Read-only order preview. This module has no runtime client, approval or refund routes. */
import { createServer, type IncomingMessage, type RequestListener, type ServerResponse } from "node:http";
import { pathToFileURL } from "node:url";
import { createAdminClient, normalizeShopDomain, toOrderGid, type ShopifyAdmin } from "./admin.js";
import { moneyToCents } from "./facts.js";
import { previewShopifyRefundOperation } from "./operations-preview.js";
import { tokenExchangeAdmin } from "./token-exchange-admin.js";
import { createSessionAuthenticator, preflight, readBody, send, type SessionServerDeps } from "./shopify-http.js";

export interface OperationsPreviewDeps extends SessionServerDeps {
  /** Order-read capability for the verified, allowlisted shop only. */
  adminFor: (shop: string, sessionToken: string) => Promise<Pick<ShopifyAdmin, "getOrder">>;
}

export function createOperationsPreviewHandler(deps: OperationsPreviewDeps): RequestListener {
  const authenticate = createSessionAuthenticator(deps);

  /** Read-only first-value endpoint: no runtime evaluation, permit or refundCreate. */
  async function handleOperationsPreview(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const who = authenticate(req, res);
    if (who === null) return;
    let body: { orderId?: unknown; amount?: unknown };
    try {
      body = JSON.parse((await readBody(req)).toString("utf8"));
    } catch {
      return send(res, 400, { error: "invalid JSON" });
    }
    if (body === null || typeof body !== "object" || typeof body.orderId !== "string" || typeof body.amount !== "string") {
      return send(res, 400, { error: "orderId and amount strings are required" });
    }
    let orderId: string;
    let amountCents: number;
    try {
      orderId = toOrderGid(body.orderId);
      amountCents = moneyToCents(body.amount);
      if (amountCents <= 0) throw new RangeError("amount must be positive");
    } catch {
      return send(res, 400, { error: "invalid order or refund amount" });
    }
    let admin: Pick<ShopifyAdmin, "getOrder">;
    try {
      admin = await deps.adminFor(who.shop, who.token);
    } catch {
      return send(res, 503, { error: "Shopify connection unavailable", mode: "read_only" });
    }
    try {
      const order = await admin.getOrder(orderId);
      if (order !== null && order.id !== orderId) {
        return send(res, 503, { error: "Shopify order identity mismatch", mode: "read_only" });
      }
      // The order read is authenticated to the session's allowlisted shop.
      // Never accept shop, customer, policy, approval or refund facts from the caller.
      return send(res, 200, previewShopifyRefundOperation(order, amountCents, deps.now?.() ?? new Date()));
    } catch {
      return send(res, 503, { error: "Shopify order facts unavailable", mode: "read_only" });
    }
  }

  return (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (req.method === "OPTIONS" && url.pathname === "/api/operations/refund-preview") {
      preflight(res);
      return;
    }
    if (req.method === "POST" && url.pathname === "/api/operations/refund-preview") {
      void handleOperationsPreview(req, res).catch(() => {
        if (!res.headersSent) send(res, 500, { error: "internal error" });
      });
    } else if (req.method === "GET" && url.pathname === "/healthz") {
      send(res, 200, { ok: true, mode: "read_only" });
    } else {
      send(res, 404, { error: "not found" });
    }
  };
}

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const clientId = requireEnv("SHOPIFY_CLIENT_ID");
  const clientSecret = requireEnv("SHOPIFY_CLIENT_SECRET");
  const shop = normalizeShopDomain(requireEnv("SHOPIFY_SHOP"));
  const staticToken = process.env.SHOPIFY_ADMIN_TOKEN;
  const adminFor = staticToken
    ? async (s: string) => createAdminClient({ shop: s, accessToken: staticToken })
    : tokenExchangeAdmin({ clientId, clientSecret });
  const port = Number(process.env.PORT ?? 3000);
  createServer(createOperationsPreviewHandler({
    clientId, clientSecret, adminFor, allowedShops: [shop],
  })).listen(port, () => console.log(`AtlaSent read-only order preview listening on :${port} for ${shop}`));
}
