/**
 * Option A: issue one gated refund from the command line.
 *
 *   npm run refund -- facts  --order 1234567890
 *   npm run refund -- refund --order 1234567890 --amount 18.99 --reason "arrived torn"
 *
 * Env: SHOPIFY_SHOP, SHOPIFY_ADMIN_TOKEN, ATLASENT_API_KEY, ATLASENT_ENVIRONMENT,
 * optional ATLASENT_BASE_URL, ATLASENT_ACTOR, LEDGER_PATH.
 * `facts` reads Shopify only and never calls AtlaSent.
 */

import { parseArgs } from "node:util";
import { AtlaSentClient } from "@atlasent/sdk";
import { createAdminClient, normalizeShopDomain } from "./admin.js";
import { centsToMoney, deriveRefundFacts, moneyToCents } from "./facts.js";
import { guardedShopifyRefund } from "./guard.js";
import { JsonFileLedger } from "./ledger.js";

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
    options: { order: { type: "string" }, amount: { type: "string" }, reason: { type: "string" } },
  });
  const command = positionals[0];
  if ((command !== "facts" && command !== "refund") || !values.order) {
    console.error("usage: refund (facts|refund) --order <id> [--amount 18.99] [--reason text]");
    return 2;
  }
  const shop = normalizeShopDomain(env("SHOPIFY_SHOP"));
  const shopify = createAdminClient({ shop, accessToken: env("SHOPIFY_ADMIN_TOKEN") });

  if (command === "facts") {
    const order = await shopify.getOrder(values.order);
    if (!order) {
      console.error("order not found");
      return 1;
    }
    const f = deriveRefundFacts(order, new Date());
    console.log(JSON.stringify({ ...f, refundable: `$${centsToMoney(f.refundable_cents)}` }, null, 2));
    return 0;
  }

  if (!values.amount) {
    console.error("--amount is required for refund");
    return 2;
  }
  const atlasent = new AtlaSentClient({
    apiKey: env("ATLASENT_API_KEY"),
    ...(process.env.ATLASENT_BASE_URL ? { baseUrl: process.env.ATLASENT_BASE_URL } : {}),
  });
  const result = await guardedShopifyRefund(
    shopify,
    atlasent,
    { orderId: values.order, amountCents: moneyToCents(values.amount), ...(values.reason ? { reason: values.reason } : {}) },
    {
      actor: process.env.ATLASENT_ACTOR ?? `shopify-cli:${process.env.USER ?? "operator"}`,
      environment: env("ATLASENT_ENVIRONMENT"),
      ledger: new JsonFileLedger(process.env.LEDGER_PATH ?? "./refund-ledger.json"),
      shop,
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
