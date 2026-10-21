/**
 * The Stripe webhook endpoint for the alarm.
 *
 *   POST /webhooks/stripe   Stripe-Signature auth -> auditStripeRefund
 *   GET  /healthz
 *
 * Subscribe the endpoint to `refund.created` in the Stripe Dashboard
 * (Developers → Webhooks) and set STRIPE_WEBHOOK_SECRET to its signing secret.
 */

import { createServer, type IncomingMessage, type RequestListener, type ServerResponse } from "node:http";
import { pathToFileURL } from "node:url";
import { JsonFileLedger, type PermitLedger } from "./ledger.js";
import { auditStripeRefund, refundFromEvent, verifyStripeSignature, type StripeRefundAuditVerdict } from "./webhook.js";

export interface StripeWebhookDeps {
  webhookSecret: string;
  ledger: PermitLedger;
  onUnauthorizedRefund?: (verdict: StripeRefundAuditVerdict) => void | Promise<void>;
  now?: () => Date;
}

const MAX_BODY = 256 * 1024;

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
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

export function createStripeWebhookHandler(deps: StripeWebhookDeps): RequestListener {
  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let raw: Buffer;
    try {
      raw = await readBody(req);
    } catch {
      return send(res, 413, { error: "too large" });
    }
    const sig = req.headers["stripe-signature"];
    const ok = verifyStripeSignature(raw, typeof sig === "string" ? sig : undefined, deps.webhookSecret, {
      ...(deps.now ? { now: deps.now() } : {}),
    });
    if (!ok) return send(res, 400, { error: "bad signature" });

    let refund;
    try {
      refund = refundFromEvent(raw);
    } catch {
      return send(res, 400, { error: "invalid JSON" });
    }
    if (refund === null) return send(res, 200, { ignored: true });
    const verdict = await auditStripeRefund(refund, deps.ledger);
    if (verdict.verdict === "unauthorized") await deps.onUnauthorizedRefund?.(verdict);
    // 200 either way: the refund already exists; a retry would change nothing.
    return send(res, 200, { verdict: verdict.verdict });
  }

  return (req, res) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    let work: Promise<void>;
    if (req.method === "POST" && path === "/webhooks/stripe") work = handle(req, res);
    else if (req.method === "GET" && path === "/healthz") work = Promise.resolve(send(res, 200, { ok: true }));
    else work = Promise.resolve(send(res, 404, { error: "not found" }));
    work.catch(() => {
      if (!res.headersSent) send(res, 500, { error: "internal error" });
    });
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) {
    console.error("STRIPE_WEBHOOK_SECRET is required");
    process.exit(2);
  }
  const port = Number(process.env.PORT ?? 3001);
  createServer(
    createStripeWebhookHandler({
      webhookSecret: secret,
      ledger: new JsonFileLedger(process.env.LEDGER_PATH ?? "./refund-ledger.json"),
      onUnauthorizedRefund: (v) => {
        // Demo alert sink. Wire this to Slack, PagerDuty or email in a real deployment.
        console.error(JSON.stringify({ alert: "stripe_refund_without_atlasent_permit", ...v }));
      },
    }),
  ).listen(port, () => console.log(`AtlaSent Stripe refund alarm listening on :${port}`));
}
