/**
 * Option D: chat with the support agent in a terminal.
 *
 *   CUSTOMER_EMAIL=robin@example.com npm run agent
 *
 * Env: as for the refund CLI, plus ANTHROPIC_API_KEY (or an `ant auth login`
 * profile) and CUSTOMER_EMAIL, which stands in for the store's own login.
 */

import { createInterface } from "node:readline/promises";
import Anthropic from "@anthropic-ai/sdk";
import { AtlaSentClient } from "@atlasent/sdk";
import { createAdminClient, normalizeShopDomain } from "./admin.js";
import { runSupportAgent } from "./agent.js";
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

const shop = normalizeShopDomain(env("SHOPIFY_SHOP"));
const shopify = createAdminClient({ shop, accessToken: env("SHOPIFY_ADMIN_TOKEN") });
const atlasent = new AtlaSentClient({
  apiKey: env("ATLASENT_API_KEY"),
  ...(process.env.ATLASENT_BASE_URL ? { baseUrl: process.env.ATLASENT_BASE_URL } : {}),
});
const environment = env("ATLASENT_ENVIRONMENT");
const ledger = new JsonFileLedger(process.env.LEDGER_PATH ?? "./refund-ledger.json");
const customerEmail = env("CUSTOMER_EMAIL");

const rl = createInterface({ input: process.stdin, output: process.stdout });
let history: Anthropic.Beta.BetaMessageParam[] = [];
console.log(`Pinecone Pet Supply support (signed in as ${customerEmail}). Ctrl+C to quit.\n`);

for (;;) {
  const line = (await rl.question("you> ")).trim();
  if (!line) continue;
  history.push({ role: "user", content: line });
  const turn = await runSupportAgent(
    {
      anthropic: new Anthropic(),
      customerEmail,
      lookupOrder: (id) => shopify.getOrder(id, { includeEmail: true }),
      refund: (req) => guardedShopifyRefund(shopify, atlasent, req, { actor: "agent:pinecone-support", environment, ledger, shop }),
    },
    history,
  );
  history = turn.messages;
  for (const r of turn.refunds) {
    console.log(`  [gate] ${r.refunded ? `refunded ${r.refund.id}` : `${r.decision}${r.denyCode ? ` ${r.denyCode}` : ""}`}`);
  }
  console.log(`agent> ${turn.reply}\n`);
}
