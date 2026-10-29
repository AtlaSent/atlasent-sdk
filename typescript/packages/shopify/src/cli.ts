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
 * Explicit agent-key identity: ATLASENT_ACTOR_IDENTITY=agent-key plus the
 * enrolled ATLASENT_ACTOR and expected ATLASENT_TENANT_ID (see README).
 * `facts` reads Shopify only and never calls AtlaSent.
 */

import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";
import { AtlaSentClient } from "@atlasent/sdk";
import { createAdminClient, normalizeShopDomain } from "./admin.js";
import { centsToMoney, deriveRefundFacts, moneyToCents } from "./facts.js";
import { guardedShopifyRefund, resumeApprovedShopifyRefund, resolveRefundActionType } from "./guard.js";
import { createApprovalsClient } from "./approvals.js";
import { JsonFileLedger } from "./ledger.js";
import { reconcileShopifyRefund } from "./reconcile.js";
import { appendEvidence } from "./evidence-log.js";
import type { RefundDecisionRecord } from "./decision-record.js";
import { refundCliIdentity, type CliEnvironment } from "./cli-identity.js";

function env(config: CliEnvironment, name: string): string {
  const v = config[name];
  if (!v) {
    console.error(`${name} is required`);
    process.exit(2);
  }
  return v;
}

export async function runRefundCli(args = process.argv.slice(2), config: CliEnvironment = { ...process.env }): Promise<number> {
  const { positionals, values } = parseArgs({
    args,
    allowPositionals: true,
    options: { order: { type: "string" }, amount: { type: "string" }, reason: { type: "string" }, approval: { type: "string" }, "request-id": { type: "string" }, "gate-ref": { type: "string" }, "refund-id": { type: "string" } },
  });
  const command = positionals[0];
  const usage = "usage: refund facts --order <id>\n       refund refund --order <id> --amount 18.99 --request-id <stable-case-id> [--reason text]\n       refund resume --approval <approval_request_id>\n       refund reconcile --gate-ref <gate_ref> [--refund-id <provider-refund-id>]";
  if (!(command === "reconcile" ? values["gate-ref"] : command === "resume" ? values.approval : (command === "facts" || command === "refund") && values.order)) {
    console.error(usage);
    return 2;
  }
  const shop = normalizeShopDomain(env(config, "SHOPIFY_SHOP"));
  const shopify = createAdminClient({ shop, accessToken: env(config, "SHOPIFY_ADMIN_TOKEN") });
  const evidenceLog = config.EVIDENCE_LOG;
  const logDecisions = evidenceLog ? { onDecision: (r: RefundDecisionRecord) => appendEvidence(evidenceLog, r) } : {};
  const actionSetting = config.ATLASENT_REFUND_ACTION_TYPE !== undefined
    ? { actionType: resolveRefundActionType(config.ATLASENT_REFUND_ACTION_TYPE) } : {};

  if (command === "reconcile") {
    const result = await reconcileShopifyRefund(shopify, new JsonFileLedger(config.LEDGER_PATH ?? "./refund-ledger.json"), {
      gateRef: values["gate-ref"]!, shop, environment: env(config, "ATLASENT_ENVIRONMENT"),
      ...(values["refund-id"] ? { candidateRefundId: values["refund-id"] } : {}),
    });
    console.log(JSON.stringify(result, null, 2));
    return result.status === "succeeded" ? 0 : 1;
  }

  if (command === "resume") {
    const apiKey = env(config, "ATLASENT_API_KEY");
    const baseUrl = config.ATLASENT_BASE_URL;
    const identity = refundCliIdentity(config, apiKey, config.ATLASENT_ACTOR ?? `shopify-cli:${config.USER ?? "operator"}`);
    const result = await resumeApprovedShopifyRefund(
      shopify,
      new AtlaSentClient({ apiKey, ...(baseUrl ? { baseUrl } : {}) }),
      createApprovalsClient({ apiKey, ...(baseUrl ? { baseUrl } : {}) }),
      { approvalRequestId: values.approval as string, resumedBy: `shopify-cli:${config.USER ?? "operator"}` },
      {
        ...identity,
        environment: env(config, "ATLASENT_ENVIRONMENT"),
        ledger: new JsonFileLedger(config.LEDGER_PATH ?? "./refund-ledger.json"),
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
  const apiKey = env(config, "ATLASENT_API_KEY");
  const identity = refundCliIdentity(config, apiKey, config.ATLASENT_ACTOR ?? `shopify-cli:${config.USER ?? "operator"}`);
  const atlasent = new AtlaSentClient({
    apiKey,
    ...(config.ATLASENT_BASE_URL ? { baseUrl: config.ATLASENT_BASE_URL } : {}),
  });
  const result = await guardedShopifyRefund(
    shopify,
    atlasent,
    { orderId, amountCents: moneyToCents(values.amount), businessRequestId: values["request-id"], ...(values.reason ? { reason: values.reason } : {}) },
    {
      ...identity,
      environment: env(config, "ATLASENT_ENVIRONMENT"),
      ledger: new JsonFileLedger(config.LEDGER_PATH ?? "./refund-ledger.json"),
      shop,
      ...logDecisions,
      ...actionSetting,
    },
  );
  console.log(JSON.stringify(result, null, 2));
  return result.refunded ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) runRefundCli().then(
  (code) => process.exit(code),
  (err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  },
);



