/**
 * App backend for the demo: the endpoint the "Refund via AtlaSent" admin
 * button calls, and the refunds/create webhook alarm.
 *
 *   POST /api/refunds               session-token auth -> guardedShopifyRefund
 *   POST /webhooks/refunds-create   HMAC auth -> auditRefundWebhook
 *   GET  /healthz
 *
 * Run: see README ("Admin button and webhook"). Plain node:http, no framework.
 */

import { createServer, type IncomingMessage, type RequestListener, type ServerResponse } from "node:http";
import { pathToFileURL } from "node:url";
import { AtlaSentClient } from "@atlasent/sdk";
import { createAdminClient, normalizeShopDomain, type ShopifyAdmin } from "./admin.js";
import { describeResult } from "./describe.js";
import { moneyToCents } from "./facts.js";
import { guardedShopifyRefund } from "./guard.js";
import { JsonFileLedger, type PermitLedger } from "./ledger.js";
import { SessionTokenError, verifySessionToken } from "./session-token.js";
import { auditRefundWebhook, verifyShopifyWebhookHmac, type RefundAuditVerdict, type RefundWebhookPayload } from "./webhook.js";

export interface GateServerDeps {
  clientId: string;
  clientSecret: string;
  environment: string;
  ledger: PermitLedger;
  atlasent: AtlaSentClient;
  /** Admin API access for a verified shop. */
  adminFor: (shop: string, sessionToken: string) => Promise<ShopifyAdmin>;
  /** Only these shops may use the gate. */
  allowedShops: string[];
  onUnauthorizedRefund?: (verdict: RefundAuditVerdict, shop: string) => void | Promise<void>;
  now?: () => Date;
}

const MAX_BODY = 64 * 1024;

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new Error("body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, {
    "content-type": "application/json",
    // Admin UI extensions call from a Shopify-hosted origin with a bearer
    // token, not cookies, so a wildcard origin grants nothing extra.
    "access-control-allow-origin": "*",
  });
  res.end(JSON.stringify(body));
}

export function createGateHandler(deps: GateServerDeps): RequestListener {
  const allowed = new Set(deps.allowedShops.map(normalizeShopDomain));

  async function handleRefund(req: IncomingMessage, res: ServerResponse): Promise<void> {
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
      return send(res, 401, { error: err instanceof SessionTokenError ? err.message : "unauthorized" });
    }
    if (!allowed.has(shop)) return send(res, 403, { error: "shop not allowed" });

    let body: { orderId?: unknown; amount?: unknown; reason?: unknown };
    try {
      body = JSON.parse((await readBody(req)).toString("utf8"));
    } catch {
      return send(res, 400, { error: "invalid JSON" });
    }
    if (typeof body.orderId !== "string" || typeof body.amount !== "string") {
      return send(res, 400, { error: "orderId and amount (e.g. \"18.99\") are required strings" });
    }
    let amountCents: number;
    try {
      amountCents = moneyToCents(body.amount);
    } catch {
      return send(res, 400, { error: "amount must look like 18.99" });
    }

    let admin: ShopifyAdmin;
    try {
      admin = await deps.adminFor(shop, token);
    } catch {
      return send(res, 502, { error: "could not get Shopify Admin API access" });
    }
    const result = await guardedShopifyRefund(
      admin,
      deps.atlasent,
      {
        orderId: body.orderId,
        amountCents,
        ...(typeof body.reason === "string" && body.reason.length > 0 ? { reason: body.reason.slice(0, 200) } : {}),
      },
      {
        actor: `shopify-staff:${shop}/${userId ?? "unknown"}`,
        environment: deps.environment,
        ledger: deps.ledger,
        shop,
        ...(deps.now ? { now: deps.now } : {}),
      },
    );
    return send(res, 200, describeResult(result));
  }

  async function handleWebhook(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let raw: Buffer;
    try {
      raw = await readBody(req);
    } catch {
      return send(res, 413, { error: "too large" });
    }
    const hmac = req.headers["x-shopify-hmac-sha256"];
    if (!verifyShopifyWebhookHmac(raw, typeof hmac === "string" ? hmac : undefined, deps.clientSecret)) {
      return send(res, 401, { error: "bad hmac" });
    }
    const topic = req.headers["x-shopify-topic"];
    const shopHeader = req.headers["x-shopify-shop-domain"];
    if (topic !== "refunds/create") return send(res, 200, { ignored: true });
    let shop: string;
    try {
      shop = normalizeShopDomain(String(shopHeader));
    } catch {
      return send(res, 400, { error: "bad shop" });
    }
    if (!allowed.has(shop)) return send(res, 200, { ignored: true });

    let payload: RefundWebhookPayload;
    try {
      payload = JSON.parse(raw.toString("utf8"));
    } catch {
      return send(res, 400, { error: "invalid JSON" });
    }
    const verdict = await auditRefundWebhook(payload, deps.ledger);
    if (verdict.verdict === "unauthorized") await deps.onUnauthorizedRefund?.(verdict, shop);
    // 200 either way: the refund already happened; a retry would change nothing.
    return send(res, 200, { verdict: verdict.verdict });
  }

  return (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const route = `${req.method} ${url.pathname}`;
    let work: Promise<void>;
    if (req.method === "OPTIONS" && url.pathname === "/api/refunds") {
      res.writeHead(204, {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "POST, OPTIONS",
        "access-control-allow-headers": "authorization, content-type",
        "access-control-max-age": "600",
      });
      res.end();
      return;
    }
    if (route === "POST /api/refunds") work = handleRefund(req, res);
    else if (route === "POST /webhooks/refunds-create") work = handleWebhook(req, res);
    else if (route === "GET /healthz") work = Promise.resolve(send(res, 200, { ok: true }));
    else work = Promise.resolve(send(res, 404, { error: "not found" }));
    work.catch(() => {
      if (!res.headersSent) send(res, 500, { error: "internal error" });
    });
  };
}

/**
 * Admin API access via Shopify token exchange: trade the session token for an
 * offline access token. Cached per shop for the life of the process.
 */
export function tokenExchangeAdmin(opts: { clientId: string; clientSecret: string; apiVersion?: string; fetch?: typeof fetch }) {
  const cache = new Map<string, string>();
  const doFetch = opts.fetch ?? fetch;
  return async (shop: string, sessionToken: string): Promise<ShopifyAdmin> => {
    let accessToken = cache.get(shop);
    if (accessToken === undefined) {
      const res = await doFetch(`https://${shop}/admin/oauth/access_token`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({
          client_id: opts.clientId,
          client_secret: opts.clientSecret,
          grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
          subject_token: sessionToken,
          subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
          requested_token_type: "urn:shopify:params:oauth:token-type:offline-access-token",
        }),
        signal: AbortSignal.timeout(10_000),
      });
      const body = (await res.json().catch(() => null)) as { access_token?: string } | null;
      if (!res.ok || typeof body?.access_token !== "string") throw new Error(`token exchange failed: HTTP ${res.status}`);
      accessToken = body.access_token;
      cache.set(shop, accessToken);
    }
    return createAdminClient({
      shop,
      accessToken,
      ...(opts.apiVersion ? { apiVersion: opts.apiVersion } : {}),
      fetch: doFetch,
    });
  };
}

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) {
    console.error(`${name} is required`);
    process.exit(2);
  }
  return v;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const clientId = requireEnv("SHOPIFY_CLIENT_ID");
  const clientSecret = requireEnv("SHOPIFY_CLIENT_SECRET");
  const shop = normalizeShopDomain(requireEnv("SHOPIFY_SHOP"));
  const environment = requireEnv("ATLASENT_ENVIRONMENT");
  const atlasent = new AtlaSentClient({
    apiKey: requireEnv("ATLASENT_API_KEY"),
    ...(process.env.ATLASENT_BASE_URL ? { baseUrl: process.env.ATLASENT_BASE_URL } : {}),
  });
  const ledger = new JsonFileLedger(process.env.LEDGER_PATH ?? "./refund-ledger.json");
  const staticToken = process.env.SHOPIFY_ADMIN_TOKEN;
  const adminFor = staticToken
    ? async (s: string) => createAdminClient({ shop: s, accessToken: staticToken })
    : tokenExchangeAdmin({ clientId, clientSecret });
  const port = Number(process.env.PORT ?? 3000);
  createServer(
    createGateHandler({
      clientId,
      clientSecret,
      environment,
      ledger,
      atlasent,
      adminFor,
      allowedShops: [shop],
      onUnauthorizedRefund: (v, s) => {
        // Demo alert sink. Wire this to Slack, PagerDuty or email in a real deployment.
        console.error(JSON.stringify({ alert: "refund_without_atlasent_permit", shop: s, ...v }));
      },
    }),
  ).listen(port, () => console.log(`AtlaSent refund gate listening on :${port} for ${shop}`));
}
