/**
 * The Stripe webhook endpoint for the alarm.
 *
 *   POST /webhooks/stripe   Stripe-Signature auth -> auditStripeRefund
 *   GET  /healthz
 *
 * Subscribe the endpoint to `refund.created`, `refund.updated` and
 * `refund.failed` in the Stripe Dashboard
 * (Developers → Webhooks) and set STRIPE_WEBHOOK_SECRET to its signing secret.
 * Set EVIDENCE_LOG to append every verdict to the evidence log (see
 * evidence-log.ts); use the same path as the CLI.
 */

import { createServer, type IncomingMessage, type RequestListener, type ServerResponse } from "node:http";
import { pathToFileURL } from "node:url";
import { JsonFileLedger, type PermitLedger } from "./ledger.js";
import { auditStripeRefund, recordRefundEvent, refundEventFromBody, verifyStripeSignature, type StripeRefundAuditVerdict } from "./webhook.js";
import { alarmRecord, appendEvidence } from "./evidence-log.js";
import type { StripeRefund } from "./stripe.js";

export interface StripeWebhookDeps {
  webhookSecret: string;
  ledger: PermitLedger;
  onUnauthorizedRefund?: (verdict: StripeRefundAuditVerdict) => void | Promise<void>;
  /** Called with every verdict, e.g. to append to the evidence log. Its failure never changes the response. */
  onVerdict?: (verdict: StripeRefundAuditVerdict, refund: StripeRefund) => void | Promise<void>;
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

    let ev;
    try {
      ev = refundEventFromBody(raw);
    } catch {
      return send(res, 400, { error: "invalid JSON" });
    }
    if (ev === null) return send(res, 200, { ignored: true });
    const refund = ev.refund;
    const record = async (): Promise<boolean> => {
      try {
        await recordRefundEvent(ev, deps.ledger, deps.now ? deps.now() : new Date());
        return true;
      } catch (err) {
        // The outcome stays unrecorded and readback (reconcileStripeRefund) still finds it; never a 2xx that hides it.
        console.error(JSON.stringify({ warning: "refund_outcome_not_recorded", eventId: ev.eventId, error: err instanceof Error ? err.message : String(err) }));
        return false;
      }
    };
    // Lifecycle events record an outcome only. The alarm runs once per refund,
    // on refund.created, so an updated refund is never alerted or counted twice.
    if (ev.type !== "refund.created") {
      if (!(await record())) return send(res, 500, { error: "outcome not recorded" });
      return send(res, 200, { recorded: true });
    }
    const verdict = await auditStripeRefund(refund, deps.ledger);
    if (verdict.verdict !== "unauthorized" && !(await record())) return send(res, 500, { error: "outcome not recorded" });
    if (verdict.verdict === "unauthorized") await deps.onUnauthorizedRefund?.(verdict);
    try {
      await deps.onVerdict?.(verdict, refund);
    } catch (err) {
      console.error(JSON.stringify({ warning: "verdict_not_logged", refundId: verdict.refundId, error: err instanceof Error ? err.message : String(err) }));
    }
    // 200 either way: the refund already exists; a retry would change nothing.
    return send(res, 200, { verdict: verdict.verdict });
  }

  return (req, res) => {
    // A request target that is not a valid path (e.g. `GET //`) makes URL throw
    // synchronously, outside work.catch: answer it rather than crash the process.
    let path: string;
    try {
      path = new URL(req.url ?? "/", "http://localhost").pathname;
    } catch {
      return send(res, 400, { error: "bad request" });
    }
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
  const evidenceLog = process.env.EVIDENCE_LOG;
  createServer(
    createStripeWebhookHandler({
      webhookSecret: secret,
      ledger: new JsonFileLedger(process.env.LEDGER_PATH ?? "./refund-ledger.json"),
      onUnauthorizedRefund: (v) => {
        // Demo alert sink. Wire this to Slack, PagerDuty or email in a real deployment.
        console.error(JSON.stringify({ alert: "stripe_refund_without_atlasent_permit", ...v }));
      },
      ...(evidenceLog ? { onVerdict: (v: StripeRefundAuditVerdict, refund: StripeRefund) => appendEvidence(evidenceLog, alarmRecord(v, refund, new Date())) } : {}),
    }),
  ).listen(port, () => console.log(`AtlaSent Stripe refund alarm listening on :${port}`));
}
