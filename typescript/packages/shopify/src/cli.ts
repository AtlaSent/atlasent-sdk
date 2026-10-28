/**
 * Option A: issue one gated refund from the command line.
 *
 *   npm run refund -- facts  --order 1234567890
 *   npm run refund -- refund --order 1234567890 --amount 18.99 --reason "arrived torn"
 *   npm run refund -- resume --approval <approval_request_id>   (after a manager decided it)
 *
 * Env: SHOPIFY_SHOP, SHOPIFY_ADMIN_TOKEN, ATLASENT_API_KEY, ATLASENT_ENVIRONMENT,
 * optional ATLASENT_BASE_URL, ATLASENT_ACTOR, LEDGER_PATH, EVIDENCE_LOG (appends each
 * decision to the evidence log; see evidence-log.ts).
 * `facts` reads Shopify only and never calls AtlaSent.
 */

import { parseArgs } from "node:util";
import { AtlaSentClient } from "@atlasent/sdk";
import { createAdminClient, normalizeShopDomain } from "./admin.js";
import { centsToMoney, deriveRefundFacts, moneyToCents } from "./facts.js";
import { guardedShopifyRefund, resumeApprovedShopifyRefund, resolveRefundActionType } from "./guard.js";
import { createApprovalsClient } from "./approvals.js";
import { JsonFileLedger } from "./ledger.js";
import { reconcileShopifyRefund } from "./reconcile.js";
import { appendEvidence } from "./evidence-log.js";
import type { RefundDecisionRecord } from "./decision-record.js";

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
    options: { order: { type: "string" }, amount: { type: "string" }, reason: { type: "string" }, approval: { type: "string" }, "request-id": { type: "string" }, "gate-ref": { type: "string" }, "refund-id": { type: "string" } },
  });
  const command = positionals[0];
  const usage = "usage: refund facts --order <id>\n       refund refund --order <id> --amount 18.99 --request-id <stable-case-id> [--reason text]\n       refund resume --approval <approval_request_id>\n       refund reconcile --gate-ref <gate_ref> [--refund-id <provider-refund-id>]";
  if (!(command === "reconcile" ? values["gate-ref"] : command === "resume" ? values.approval : (command === "facts" || command === "refund") && values.order)) {
    console.error(usage);
    return 2;
  }
  const shop = normalizeShopDomain(env("SHOPIFY_SHOP"));
  const shopify = createAdminClient({ shop, accessToken: env("SHOPIFY_ADMIN_TOKEN") });
  const evidenceLog = process.env.EVIDENCE_LOG;
  const logDecisions = evidenceLog ? { onDecision: (r: RefundDecisionRecord) => appendEvidence(evidenceLog, r) } : {};
  const actionSetting = process.env.ATLASENT_REFUND_ACTION_TYPE !== undefined
    ? { actionType: resolveRefundActionType(process.env.ATLASENT_REFUND_ACTION_TYPE) } : {};

  if (command === "reconcile") {
    const result = await reconcileShopifyRefund(shopify, new JsonFileLedger(process.env.LEDGER_PATH ?? "./refund-ledger.json"), {
      gateRef: values["gate-ref"]!, shop, environment: env("ATLASENT_ENVIRONMENT"),
      ...(values["refund-id"] ? { candidateRefundId: values["refund-id"] } : {}),
    });
    console.log(JSON.stringify(result, null, 2));
    return result.status === "succeeded" ? 0 : 1;
  }

  if (command === "resume") {
    const apiKey = env("ATLASENT_API_KEY");
    const baseUrl = process.env.ATLASENT_BASE_URL;
    const result = await resumeApprovedShopifyRefund(
      shopify,
      new AtlaSentClient({ apiKey, ...(baseUrl ? { baseUrl } : {}) }),
      createApprovalsClient({ apiKey, ...(baseUrl ? { baseUrl } : {}) }),
      { approvalRequestId: values.approval as string, resumedBy: `shopify-cli:${process.env.USER ?? "operator"}` },
      {
        actor: process.env.ATLASENT_ACTOR ?? `shopify-cli:${process.env.USER ?? "operator"}`,
        environment: env("ATLASENT_ENVIRONMENT"),
        ledger: new JsonFileLedger(process.env.LEDGER_PATH ?? "./refund-ledger.json"),
        shop,
        ...logDecisions,
        ...actionSetting,
      },
    );
    console.log(JSON.stringify(result, null, 2));
    return result.refunded ? 0 : 1;
  }
  const orderId = values.order as string;

  if (command === "facts") {
    const order = await shopify.getOrder(orderId);
    if (!order) {
      console.error("order not found");
      return 1;
    }
    const f = deriveRefundFacts(order, new Date());
    console.log(JSON.stringify({ ...f, refundable: `$${centsToMoney(f.refundable_cents)}` }, null, 2));
    return 0;
  }

  if (!values.amount || !values["request-id"]) {
    console.error("--amount and --request-id are required for refund; reuse the original request ID on retries");
    return 2;
  }
  const atlasent = new AtlaSentClient({
    apiKey: env("ATLASENT_API_KEY"),
    ...(process.env.ATLASENT_BASE_URL ? { baseUrl: process.env.ATLASENT_BASE_URL } : {}),
  });
  const result = await guardedShopifyRefund(
    shopify,
    atlasent,
    { orderId, amountCents: moneyToCents(values.amount), businessRequestId: values["request-id"], ...(values.reason ? { reason: values.reason } : {}) },
    {
      actor: process.env.ATLASENT_ACTOR ?? `shopify-cli:${process.env.USER ?? "operator"}`,
      environment: env("ATLASENT_ENVIRONMENT"),
      ledger: new JsonFileLedger(process.env.LEDGER_PATH ?? "./refund-ledger.json"),
      shop,
      ...logDecisions,
      ...actionSetting,
    },
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


