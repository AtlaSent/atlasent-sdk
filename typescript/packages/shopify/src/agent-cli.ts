/**
 * Option D: chat with the support agent in a terminal.
 *
 *   CUSTOMER_EMAIL=robin@example.com npm run agent
 *
 * Env: as for the refund CLI, plus ANTHROPIC_API_KEY (or an `ant auth login`
 * profile) and CUSTOMER_EMAIL, which stands in for the store's own login.
 */

import { createInterface } from "node:readline/promises";
import { pathToFileURL } from "node:url";
import Anthropic from "@anthropic-ai/sdk";
import { AtlaSentClient } from "@atlasent/sdk";
import { createAdminClient, normalizeShopDomain } from "./admin.js";
import { runSupportAgent } from "./agent.js";
import { guardedShopifyRefund, resolveRefundActionType } from "./guard.js";
import { appendEvidence } from "./evidence-log.js";
import type { RefundDecisionRecord } from "./decision-record.js";
import { JsonFileLedger } from "./ledger.js";
import { refundCliIdentity, type CliEnvironment } from "./cli-identity.js";

function env(config: CliEnvironment, name: string): string {
  const v = config[name];
  if (!v) {
    console.error(`${name} is required`);
    process.exit(2);
  }
  return v;
}

export async function runSupportAgentCli(config: CliEnvironment = { ...process.env }): Promise<void> {
  const shop = normalizeShopDomain(env(config, "SHOPIFY_SHOP"));
  const shopify = createAdminClient({ shop, accessToken: env(config, "SHOPIFY_ADMIN_TOKEN") });
  const apiKey = env(config, "ATLASENT_API_KEY");
  const identity = refundCliIdentity(config, apiKey, "agent:pinecone-support");
  const atlasent = new AtlaSentClient({
    apiKey,
    ...(config.ATLASENT_BASE_URL ? { baseUrl: config.ATLASENT_BASE_URL } : {}),
  });
  const environment = env(config, "ATLASENT_ENVIRONMENT");
  const actionSetting = config.ATLASENT_REFUND_ACTION_TYPE !== undefined
    ? { actionType: resolveRefundActionType(config.ATLASENT_REFUND_ACTION_TYPE) } : {};
  const ledger = new JsonFileLedger(config.LEDGER_PATH ?? "./refund-ledger.json");
  const customerEmail = env(config, "CUSTOMER_EMAIL");
  const businessRequestId = env(config, "SUPPORT_CASE_ID");
  const evidenceLog = config.EVIDENCE_LOG;

  const rl = createInterface({ input: process.stdin, output: process.stdout });
  let history: Anthropic.Beta.BetaMessageParam[] = [];
  console.log(`Pinecone Pet Supply support (signed in as ${customerEmail}). Ctrl+C to quit.\n`);

  try {
    for (;;) {
      const line = (await rl.question("you> ")).trim();
      if (!line) continue;
      history.push({ role: "user", content: line });
      const turn = await runSupportAgent(
        {
          anthropic: new Anthropic(),
          customerEmail,
          businessRequestId,
          lookupOrder: (id) => shopify.getOrder(id, { includeEmail: true }),
          refund: (req) =>
            guardedShopifyRefund(shopify, atlasent, req, {
              ...identity,
              environment,
              ledger,
              shop,
              ...actionSetting,
              ...(evidenceLog ? { onDecision: (r: RefundDecisionRecord) => appendEvidence(evidenceLog, r) } : {}),
            }),
        },
        history,
      );
      history = turn.messages;
      for (const r of turn.refunds) {
        console.log(`  [gate] ${r.refunded ? `refunded ${r.refund.id}` : `${r.decision}${r.denyCode ? ` ${r.denyCode}` : ""}`}`);
      }
      console.log(`agent> ${turn.reply}\n`);
    }
  } finally {
    rl.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runSupportAgentCli().catch(err => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  });
}
