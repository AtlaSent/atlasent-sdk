/**
 * Issue one gated Stripe refund from the command line.
 *
 *   npm run refund -- facts  --payment pi_123
 *   npm run refund -- refund --payment pi_123 --amount 18.99 --reason "arrived torn"
 *   npm run refund -- resume --approval <approval_request_id>   (after a manager decided it)
 *
 * Env: STRIPE_SECRET_KEY (use a test-mode restricted key), ATLASENT_API_KEY,
 * ATLASENT_ENVIRONMENT, DELIVERY_FACTS_FILE; optional ATLASENT_BASE_URL,
 * ATLASENT_ACTOR, STRIPE_ACCOUNT_LABEL, ORDER_REF_KEY, LEDGER_PATH, EVIDENCE_LOG
 * (appends each decision to the evidence log; see evidence-log.ts).
 *
 * DELIVERY_FACTS_FILE stands in for the store's order system: a JSON map of
 * order reference -> { "order_status": "delivered", "delivered_at": "<ISO>" }.
 * `facts` reads Stripe and that file only, and never calls AtlaSent.
 */

import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { AtlaSentClient } from "@atlasent/sdk";
import { centsToMoney, deriveStripeRefundFacts, moneyToCents, staticDeliveryFacts, type DeliveryFacts } from "./facts.js";
import { guardedStripeRefund, resumeApprovedStripeRefund } from "./guard.js";
import { createApprovalsClient } from "./approvals.js";
import { appendEvidence } from "./evidence-log.js";
import type { RefundDecisionRecord } from "./decision-record.js";
import { JsonFileLedger } from "./ledger.js";
import { createStripeClient } from "./stripe.js";

function env(name: string): string {
  const v = process.env[name];
  if (!v) {
    console.error(`${name} is required`);
    process.exit(2);
  }
  return v;
}

async function main(): Promise<number> {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: { payment: { type: "string" }, amount: { type: "string" }, reason: { type: "string" }, approval: { type: "string" } },
  });
  const command = positionals[0];
  if (!(command === "resume" ? values.approval : (command === "facts" || command === "refund") && values.payment)) {
    console.error("usage: refund (facts|refund) --payment pi_... [--amount 18.99] [--reason text]\n       refund resume --approval <approval_request_id>");
    return 2;
  }
  const secretKey = env("STRIPE_SECRET_KEY");
  if (secretKey.startsWith("sk_live_") || secretKey.startsWith("rk_live_")) {
    console.error("Refusing a live-mode Stripe key: this demo runs in test mode only.");
    return 2;
  }
  const stripe = createStripeClient({ secretKey });
  const delivery = staticDeliveryFacts(JSON.parse(readFileSync(env("DELIVERY_FACTS_FILE"), "utf8")) as Record<string, DeliveryFacts>);
  const orderRefKey = process.env.ORDER_REF_KEY ?? "order_id";
  const actor = process.env.ATLASENT_ACTOR ?? `stripe-cli:${process.env.USER ?? "operator"}`;
  const evidenceLog = process.env.EVIDENCE_LOG;
  const gateOptions = () => ({
    ...(evidenceLog ? { onDecision: (r: RefundDecisionRecord) => appendEvidence(evidenceLog, r) } : {}),
    actor,
    environment: env("ATLASENT_ENVIRONMENT"),
    ledger: new JsonFileLedger(process.env.LEDGER_PATH ?? "./refund-ledger.json"),
    delivery,
    account: process.env.STRIPE_ACCOUNT_LABEL ?? "default",
    orderRefKey,
  });
  const apiKey = () => env("ATLASENT_API_KEY");
  const baseUrl = process.env.ATLASENT_BASE_URL;

  if (command === "resume") {
    const key = apiKey();
    const result = await resumeApprovedStripeRefund(
      stripe,
      new AtlaSentClient({ apiKey: key, ...(baseUrl ? { baseUrl } : {}) }),
      createApprovalsClient({ apiKey: key, ...(baseUrl ? { baseUrl } : {}) }),
      { approvalRequestId: values.approval as string, resumedBy: actor },
      gateOptions(),
    );
    console.log(JSON.stringify(result, null, 2));
    return result.refunded ? 0 : 1;
  }
  const paymentId = values.payment as string;

  if (command === "facts") {
    const pi = await stripe.getPaymentIntent(paymentId);
    if (!pi) {
      console.error("payment not found");
      return 1;
    }
    const ref = pi.metadata?.[orderRefKey] ?? null;
    const f = deriveStripeRefundFacts(pi, ref ? await delivery.getDeliveryFacts(ref) : null, ref, new Date());
    console.log(JSON.stringify({ ...f, refundable: `$${centsToMoney(f.refundable_cents)}` }, null, 2));
    return 0;
  }

  if (!values.amount) {
    console.error("--amount is required for refund");
    return 2;
  }
  const atlasent = new AtlaSentClient({ apiKey: apiKey(), ...(baseUrl ? { baseUrl } : {}) });
  const result = await guardedStripeRefund(
    stripe,
    atlasent,
    { paymentIntentId: paymentId, amountCents: moneyToCents(values.amount), ...(values.reason ? { reason: values.reason } : {}) },
    gateOptions(),
  );
  console.log(JSON.stringify(result, null, 2));
  return result.refunded ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  },
);
