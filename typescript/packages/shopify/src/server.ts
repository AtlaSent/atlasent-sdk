/**
 * Explicit write-capable refund demo backend and refunds/create webhook alarm.
 * Default `npm run serve` uses preview-server.ts instead.
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
import { createOperationsPreviewHandler } from "./preview-server.js";
import { createSessionAuthenticator, preflight, readBody, send } from "./shopify-http.js";
import { tokenExchangeAdmin } from "./token-exchange-admin.js";
export { tokenExchangeAdmin } from "./token-exchange-admin.js";
import { describeResult } from "./describe.js";
import { moneyToCents } from "./facts.js";
import { guardedShopifyRefund, resumeApprovedShopifyRefund } from "./guard.js";
import { reconcileShopifyRefund } from "./reconcile.js";
import { createApprovalsClient, type ApprovalsApi } from "./approvals.js";
import type { RefundDecisionRecord } from "./decision-record.js";
import { JsonFileLedger, type PermitLedger } from "./ledger.js";
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

export function createGateHandler(deps: GateServerDeps): RequestListener {
  const allowed = new Set(deps.allowedShops.map(normalizeShopDomain));

  const authenticate = createSessionAuthenticator(deps);
  const previewHandler = createOperationsPreviewHandler(deps);

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
    if (!body || typeof body !== "object" || typeof body.approvalRequestId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(body.approvalRequestId)) {
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

    let body: { orderId?: unknown; amount?: unknown; reason?: unknown; businessRequestId?: unknown };
    try {
      body = JSON.parse((await readBody(req)).toString("utf8"));
    } catch {
      return send(res, 400, { error: "invalid JSON" });
    }
    if (!body || typeof body !== "object" || typeof body.orderId !== "string" || typeof body.amount !== "string") {
      return send(res, 400, { error: "orderId and amount (e.g. \"18.99\") are required strings" });
    }
    if (typeof body.businessRequestId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(body.businessRequestId)) {
      return send(res, 400, { error: "businessRequestId is required; reuse the original case ID on retries" });
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
        businessRequestId: body.businessRequestId,
        ...(typeof body.reason === "string" && body.reason.length > 0 ? { reason: body.reason.slice(0, 200) } : {}),
      },
      gateOptions(shop, userId),
    );
    warnIfNotLogged(result);
    return send(res, 200, describeResult(result));
  }

  async function handleReconcile(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const who = authenticate(req, res);
    if (who === null) return;
    let body: { gateRef?: unknown; candidateRefundId?: unknown };
    try { body = JSON.parse((await readBody(req)).toString("utf8")); }
    catch { return send(res, 400, { error: "invalid JSON" }); }
    if (!body || typeof body !== "object" || typeof body.gateRef !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(body.gateRef) ||
        (body.candidateRefundId !== undefined && (typeof body.candidateRefundId !== "string" || !/^gid:\/\/shopify\/Refund\/\d+$/.test(body.candidateRefundId)))) {
      return send(res, 400, { error: "gateRef and an optional Shopify refund ID are required" });
    }
    let admin: ShopifyAdmin;
    try { admin = await deps.adminFor(who.shop, who.token); }
    catch { return send(res, 502, { error: "could not get Shopify Admin API access" }); }
    return send(res, 200, await reconcileShopifyRefund(admin, deps.ledger, {
      gateRef: body.gateRef, shop: who.shop, environment: deps.environment,
      ...(typeof body.candidateRefundId === "string" ? { candidateRefundId: body.candidateRefundId } : {}),
    }));
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
    if (url.pathname === "/api/operations/refund-preview") {
      previewHandler(req, res);
      return;
    }
    let work: Promise<void>;
    if (req.method === "OPTIONS" && ["/api/refunds", "/api/refunds/resume", "/api/refunds/reconcile"].includes(url.pathname)) {
      preflight(res);
      return;
    }
    if (route === "POST /api/refunds") work = handleRefund(req, res);
    else if (route === "POST /api/refunds/resume") work = handleResume(req, res);
    else if (route === "POST /api/refunds/reconcile") work = handleReconcile(req, res);
    else if (route === "POST /webhooks/refunds-create") work = handleWebhook(req, res);
    else if (route === "GET /healthz") work = Promise.resolve(send(res, 200, { ok: true }));
    else work = Promise.resolve(send(res, 404, { error: "not found" }));
    work.catch(() => {
      if (!res.headersSent) send(res, 500, { error: "internal error" });
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


