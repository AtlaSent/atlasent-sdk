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
import { guardedShopifyRefund, resumeApprovedShopifyRefund } from "./guard.js";
import { createApprovalsClient, type ApprovalsApi } from "./approvals.js";
import type { RefundDecisionRecord } from "./decision-record.js";
import { JsonFileLedger, type PermitLedger } from "./ledger.js";
import { SessionTokenError, verifySessionToken } from "./session-token.js";
import { auditRefundWebhook, verifyShopifyWebhookHmac, type RefundAuditVerdict, type RefundWebhookPayload } from "./webhook.js";
import { alarmRecord, appendEvidence } from "./evidence-log.js";

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
  /** Reads manager decisions on escalated refunds (POST /api/refunds/resume). */
  approvals?: ApprovalsApi;
  /** Evidence log: one record per refund decision. */
  onDecision?: (record: RefundDecisionRecord) => void | Promise<void>;
  /** Called with every refunds/create verdict, e.g. to append to the evidence log. Its failure never changes the response. */
  onVerdict?: (verdict: RefundAuditVerdict, payload: RefundWebhookPayload, shop: string) => void | Promise<void>;
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

  const gateOptions = (shop: string, userId: string | undefined) => ({
    actor: `shopify-staff:${shop}/${userId ?? "unknown"}`,
    environment: deps.environment,
    ledger: deps.ledger,
    shop,
    ...(deps.now ? { now: deps.now } : {}),
    ...(deps.onDecision ? { onDecision: deps.onDecision } : {}),
  });

  async function handleResume(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const who = authenticate(req, res);
    if (who === null) return;
    if (deps.approvals === undefined) return send(res, 501, { error: "manager approvals are not configured on this server" });
    let body: { approvalRequestId?: unknown };
    try {
      body = JSON.parse((await readBody(req)).toString("utf8"));
    } catch {
      return send(res, 400, { error: "invalid JSON" });
    }
    if (typeof body.approvalRequestId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(body.approvalRequestId)) {
      return send(res, 400, { error: "approvalRequestId is required" });
    }
    let admin: ShopifyAdmin;
    try {
      admin = await deps.adminFor(who.shop, who.token);
    } catch {
      return send(res, 502, { error: "could not get Shopify Admin API access" });
    }
    const result = await resumeApprovedShopifyRefund(
      admin,
      deps.atlasent,
      deps.approvals,
      { approvalRequestId: body.approvalRequestId, resumedBy: `shopify-staff:${who.shop}/${who.userId ?? "unknown"}` },
      gateOptions(who.shop, who.userId),
    );
    warnIfNotLogged(result);
    return send(res, 200, describeResult(result));
  }

  async function handleRefund(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const who = authenticate(req, res);
    if (who === null) return;
    const { shop, userId, token } = who;

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
      gateOptions(shop, userId),
    );
    warnIfNotLogged(result);
    return send(res, 200, describeResult(result));
  }

  /** The decision stands, but the evidence log lost it: say so where the operator looks. */
  function warnIfNotLogged(result: { gateRef: string; logWarning?: string }): void {
    if (result.logWarning !== undefined) {
      console.error(JSON.stringify({ warning: "decision_not_logged", gateRef: result.gateRef, error: result.logWarning }));
    }
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
    try {
      await deps.onVerdict?.(verdict, payload, shop);
    } catch (err) {
      console.error(JSON.stringify({ warning: "verdict_not_logged", refundId: verdict.refundId, error: err instanceof Error ? err.message : String(err) }));
    }
    // 200 either way: the refund already happened; a retry would change nothing.
    return send(res, 200, { verdict: verdict.verdict });
  }

  return (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const route = `${req.method} ${url.pathname}`;
    let work: Promise<void>;
    if (req.method === "OPTIONS" && (url.pathname === "/api/refunds" || url.pathname === "/api/refunds/resume")) {
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
    else if (route === "POST /api/refunds/resume") work = handleResume(req, res);
    else if (route === "POST /webhooks/refunds-create") work = handleWebhook(req, res);
    else if (route === "GET /healthz") work = Promise.resolve(send(res, 200, { ok: true }));
    else work = Promise.resolve(send(res, 404, { error: "not found" }));
    work.catch(() => {
      if (!res.headersSent) send(res, 500, { error: "internal error" });
    });
  };
}

/**
 * Admin API access via Shopify token exchange: trade the staff member's
 * session token for an offline access token.
 *
 * Requests an expiring token (`expiring: "1"`) and caches it only until
 * shortly before `expires_in`. Every request to this backend carries a fresh
 * session token, so an expired token is simply exchanged again; no refresh
 * token is stored. A response without `expires_in` (a non-expiring token)
 * is cached for the life of the process.
 */
export function tokenExchangeAdmin(opts: {
  clientId: string;
  clientSecret: string;
  apiVersion?: string;
  fetch?: typeof fetch;
  now?: () => number;
}) {
  const cache = new Map<string, { token: string; expiresAt: number }>();
  const doFetch = opts.fetch ?? fetch;
  const now = opts.now ?? Date.now;
  return async (shop: string, sessionToken: string): Promise<ShopifyAdmin> => {
    const hit = cache.get(shop);
    let accessToken = hit !== undefined && hit.expiresAt > now() ? hit.token : undefined;
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
          expiring: "1",
        }),
        signal: AbortSignal.timeout(10_000),
      });
      const body = (await res.json().catch(() => null)) as { access_token?: string; expires_in?: number } | null;
      if (!res.ok || typeof body?.access_token !== "string") throw new Error(`token exchange failed: HTTP ${res.status}`);
      accessToken = body.access_token;
      const ttlMs = typeof body.expires_in === "number" && body.expires_in > 0 ? body.expires_in * 1000 : Infinity;
      // Refresh a minute early so a token never expires mid-refund.
      cache.set(shop, { token: accessToken, expiresAt: now() + Math.max(0, ttlMs - 60_000) });
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
  const evidenceLog = process.env.EVIDENCE_LOG;
  createServer(
    createGateHandler({
      clientId,
      clientSecret,
      environment,
      ledger,
      atlasent,
      adminFor,
      allowedShops: [shop],
      approvals: createApprovalsClient({
        apiKey: requireEnv("ATLASENT_API_KEY"),
        ...(process.env.ATLASENT_BASE_URL ? { baseUrl: process.env.ATLASENT_BASE_URL } : {}),
      }),
      onUnauthorizedRefund: (v, s) => {
        // Demo alert sink. Wire this to Slack, PagerDuty or email in a real deployment.
        console.error(JSON.stringify({ alert: "refund_without_atlasent_permit", shop: s, ...v }));
      },
      ...(evidenceLog
        ? {
            onDecision: (r: RefundDecisionRecord) => appendEvidence(evidenceLog, r),
            onVerdict: (v: RefundAuditVerdict, p: RefundWebhookPayload) => appendEvidence(evidenceLog, alarmRecord(v, p, new Date())),
          }
        : {}),
    }),
  ).listen(port, () => console.log(`AtlaSent refund gate listening on :${port} for ${shop}`));
}
