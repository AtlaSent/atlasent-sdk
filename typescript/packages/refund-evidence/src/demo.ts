/**
 * One policy, three refund paths, one evidence report.
 *
 *   npm run demo                       # simulated stores + local policy stand-in
 *   ATLASENT_API_KEY=... ATLASENT_ENVIRONMENT=test npm run demo
 *                                      # simulated stores, REAL AtlaSent decisions
 *
 * Runs the Pinecone Pet Supply scenarios through:
 *   - the Shopify gate, as the "Refund via AtlaSent" admin button would;
 *   - the support agent's issue_refund tool (the code path the AI agent calls);
 *   - the Stripe gate, for payments taken directly through Stripe.
 * A manager then approves the Shopify escalation (which the gate resumes and
 * refunds, exactly as escalated) and declines the Stripe one. Two refunds are
 * then made AROUND the gate (Shopify admin, Stripe Dashboard),
 * runs every refund the platforms report through the alarms, and writes:
 *   evidence-out/decisions.jsonl   the log
 *   evidence-out/report.html       the report a finance reader opens
 *   evidence-out/report.csv        the same rows for a spreadsheet
 *
 * The stores are always simulated here; no money moves. The report says so.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { AtlaSentClient } from "@atlasent/sdk";
import { guardedShopifyRefund, resumeApprovedShopifyRefund } from "../../shopify/src/guard.js";
import type { ApprovalsApi } from "../../shopify/src/approvals.js";
import { InMemoryLedger as ShopifyLedger } from "../../shopify/src/ledger.js";
import { auditRefundWebhook } from "../../shopify/src/webhook.js";
import { runSupportTool, type SupportAgentDeps } from "../../shopify/src/agent.js";
import { guardedStripeRefund, resumeApprovedStripeRefund } from "../../stripe/src/guard.js";
import { InMemoryLedger as StripeLedger } from "../../stripe/src/ledger.js";
import { auditStripeRefund } from "../../stripe/src/webhook.js";
import { staticDeliveryFacts } from "../../stripe/src/facts.js";
import { REFUND_ALARM_SCHEMA, type RefundAlarmRecord, type RefundDecisionRecord } from "./records.js";
import { buildEvidenceReport, formatMoney, outcomeText, type EvidenceReport } from "./report.js";
import { createSimulatedRuntime, SimShopify, SimStripe } from "./sim.js";

const DAY_MS = 86_400_000;
const SHOP = "pinecone-pet-supply.myshopify.com";

export interface DemoOptions {
  atlasent: AtlaSentClient;
  /** True when `atlasent` is the local stand-in, not the real runtime. */
  simulatedDecisions: boolean;
  environment: string;
  now: () => Date;
  log?: (line: string) => void;
  /**
   * Plays the manager deciding escalations in the AtlaSent console. Only the
   * local stand-in has one; against the real runtime a person decides, and the
   * demo leaves the escalations waiting.
   */
  manager?: { approvals: ApprovalsApi; decide(approvalRequestId: string, status: "approved" | "denied"): void };
}

export interface DemoResult {
  decisions: RefundDecisionRecord[];
  alarms: RefundAlarmRecord[];
  report: EvidenceReport;
  /** The agent's refusal of another customer's order (never reaches the gate). */
  agentOwnershipRefusal: string;
}

export async function runDemo(opts: DemoOptions): Promise<DemoResult> {
  const now = opts.now;
  const say = opts.log ?? (() => {});
  const decisions: RefundDecisionRecord[] = [];
  const alarms: RefundAlarmRecord[] = [];
  const onDecision = (r: RefundDecisionRecord) => {
    decisions.push(r);
    say(`  ${r.system.padEnd(7)} ${(r.order_ref ?? r.target).padEnd(12)} ${formatMoney(r.amount_cents, r.currency).padStart(8)}  ${outcomeText(r)}${r.deny_code ? ` (${r.deny_code})` : ""}`);
  };

  const shopify = new SimShopify(
    [
      { id: 1001, email: "robin@example.com", paid: "34.99", delivery: "delivered", daysAgo: 5 },
      { id: 1002, email: "sam@example.com", paid: "129.00", delivery: "delivered", daysAgo: 3 },
      { id: 1003, email: "kai@example.com", paid: "24.50", delivery: "in_transit", daysAgo: 0 },
      { id: 1004, email: "alex@example.com", paid: "42.00", delivery: "delivered", daysAgo: 45 },
      { id: 1005, email: "jo@example.com", paid: "19.99", delivery: "delivered", daysAgo: 10 },
    ],
    now(),
  );
  const shopifyLedger = new ShopifyLedger();
  const shopifyOptions = (actor: string) => ({ actor, environment: opts.environment, ledger: shopifyLedger, shop: SHOP, now, onDecision });
  const shopifyGate = (actor: string) => (req: { orderId: string; amountCents: number; reason?: string }) =>
    guardedShopifyRefund(shopify, opts.atlasent, req, shopifyOptions(actor));

  say("Shopify admin button (staff member Dana):");
  const dana = `shopify-staff:${SHOP}/dana`;
  const staff = shopifyGate(dana);
  await staff({ orderId: "1001", amountCents: 1899, reason: "chew toy arrived torn" });
  const shopifyEscalation = await staff({ orderId: "1002", amountCents: 7200, reason: "wrong size cat tree" });
  await staff({ orderId: "1003", amountCents: 1200, reason: "still in transit" });
  await staff({ orderId: "1004", amountCents: 2500, reason: "asked 45 days after delivery" });

  say("Support agent's refund tool (customer signed in as jo@example.com):");
  const agentDeps = (customerEmail: string): SupportAgentDeps => ({
    // runSupportTool never calls the model; only runSupportAgent does.
    anthropic: undefined as never,
    customerEmail,
    now,
    lookupOrder: (id) => shopify.getOrder(id, { includeEmail: true }),
    refund: shopifyGate("agent:pinecone-support"),
  });
  await runSupportTool("issue_refund", { order_id: "1005", amount: "19.99", reason: "treats arrived stale" }, agentDeps("jo@example.com"), []);
  const refusal = await runSupportTool("issue_refund", { order_id: "1005", amount: "19.99", reason: "not my order" }, agentDeps("robin@example.com"), []);
  say(`  agent   #PPS-1005 asked for by robin@example.com: ${refusal.content}`);

  say("Stripe gate (payments taken directly through Stripe):");
  const stripe = new SimStripe(
    [
      { id: "pi_2001", orderRef: "PPS-2001", captured: 2900 },
      { id: "pi_2002", orderRef: "PPS-2002", captured: 8500 },
    ],
    now(),
  );
  const stripeLedger = new StripeLedger();
  const delivered = (days: number) => ({ order_status: "delivered" as const, delivered_at: new Date(now().getTime() - days * DAY_MS).toISOString() });
  const stripeOptions = {
    actor: "support-tool:dana",
    environment: opts.environment,
    ledger: stripeLedger,
    delivery: staticDeliveryFacts({ "PPS-2001": delivered(7), "PPS-2002": delivered(2) }),
    account: "acct_pinecone_demo",
    now,
    onDecision,
  };
  await guardedStripeRefund(stripe, opts.atlasent, { paymentIntentId: "pi_2001", amountCents: 2900, reason: "never arrived, carrier confirmed loss" }, stripeOptions);
  const stripeEscalation = await guardedStripeRefund(stripe, opts.atlasent, { paymentIntentId: "pi_2002", amountCents: 8500, reason: "changed mind" }, stripeOptions);

  const shopifyApproval = shopifyEscalation.refunded ? undefined : shopifyEscalation.approvalRequestId;
  const stripeApproval = stripeEscalation.refunded ? undefined : stripeEscalation.approvalRequestId;
  if (opts.manager) {
    say("Manager decisions in the AtlaSent console, then the gates resume:");
    if (shopifyApproval) {
      opts.manager.decide(shopifyApproval, "approved");
      await resumeApprovedShopifyRefund(shopify, opts.atlasent, opts.manager.approvals, { approvalRequestId: shopifyApproval, resumedBy: dana }, shopifyOptions(dana));
    }
    if (stripeApproval) {
      opts.manager.decide(stripeApproval, "denied");
      await resumeApprovedStripeRefund(stripe, opts.atlasent, opts.manager.approvals, { approvalRequestId: stripeApproval, resumedBy: "support-tool:dana" }, stripeOptions);
    }
  } else {
    say("Escalations wait for a person in the AtlaSent console; resume each with `npm run refund -- resume --approval <id>`:");
    for (const id of [shopifyApproval, stripeApproval]) say(`  ${id ?? "(the runtime returned no approval request id)"}`);
  }

  say("Refunds made around the gate:");
  shopify.adminRefund("gid://shopify/Order/1004", "25.00", "customer asked nicely");
  say("  shopify #PPS-1004 $25.00 refunded by a staff member in the Shopify admin, after the policy declined it");
  stripe.dashboardRefund("pi_2002", 8500);
  say("  stripe  pi_2002   $85.00 refunded by a teammate in the Stripe Dashboard, after the manager declined it");

  for (const payload of shopify.webhooks) {
    const v = await auditRefundWebhook(payload, shopifyLedger);
    alarms.push({
      schema: REFUND_ALARM_SCHEMA,
      at: now().toISOString(),
      system: "shopify",
      refund_id: v.refundId,
      target: `gid://shopify/Order/${v.orderId}`,
      amount_cents: v.amountCents,
      currency: "USD",
      verdict: v.verdict,
      reason: v.verdict === "unauthorized" ? v.reason : null,
      gate_ref: v.gateRef ?? null,
    });
  }
  for (const refund of stripe.events) {
    const v = await auditStripeRefund(refund, stripeLedger);
    alarms.push({
      schema: REFUND_ALARM_SCHEMA,
      at: now().toISOString(),
      system: "stripe",
      refund_id: v.refundId,
      target: v.verdict === "ignored" ? null : v.paymentIntent,
      amount_cents: v.verdict === "ignored" ? null : v.amountCents,
      currency: refund.currency.toUpperCase(),
      verdict: v.verdict,
      reason: v.verdict === "authorized" ? null : v.reason,
      gate_ref: v.verdict === "ignored" ? null : (v.gateRef ?? null),
    });
  }
  const flagged = alarms.filter((a) => a.verdict === "unauthorized");
  say(`Alarm: ${alarms.length - flagged.length} platform refund(s) matched a permit, ${flagged.length} flagged.`);

  const report = buildEvidenceReport({
    decisions,
    alarms,
    storeName: "Pinecone Pet Supply (fictional)",
    generatedAt: now(),
    simulated: { stores: true, decisions: opts.simulatedDecisions },
  });
  return { decisions, alarms, report, agentOwnershipRefusal: refusal.content };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const apiKey = process.env.ATLASENT_API_KEY;
  const live = typeof apiKey === "string" && apiKey.length > 0;
  if (live && !process.env.ATLASENT_ENVIRONMENT) {
    console.error("ATLASENT_ENVIRONMENT is required with ATLASENT_API_KEY");
    process.exit(2);
  }
  const sim = live ? undefined : createSimulatedRuntime();
  const atlasent = sim ? sim.client : new AtlaSentClient({ apiKey: apiKey as string, ...(process.env.ATLASENT_BASE_URL ? { baseUrl: process.env.ATLASENT_BASE_URL } : {}) });
  console.log(live ? "AtlaSent decisions: LIVE runtime. Stores: simulated.\n" : "AtlaSent decisions: LOCAL STAND-IN (simulated). Stores: simulated.\n");
  const outDir = process.env.EVIDENCE_OUT ?? "evidence-out";
  const result = await runDemo({
    atlasent,
    simulatedDecisions: !live,
    environment: process.env.ATLASENT_ENVIRONMENT ?? "test",
    now: () => new Date(),
    log: (l) => console.log(l),
    ...(sim ? { manager: sim } : {}),
  });
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "decisions.jsonl"), [...result.decisions, ...result.alarms].map((r) => JSON.stringify(r)).join("\n") + "\n");
  writeFileSync(join(outDir, "report.html"), result.report.html);
  writeFileSync(join(outDir, "report.csv"), result.report.csv);
  const s = result.report.summary;
  console.log(`\nRefunded ${s.refunded.count}, sent to a manager ${s.escalated.count}, declined ${s.declined.count}, made outside the gate ${s.outsideGate.count}.`);
  console.log(`Wrote ${join(outDir, "report.html")}, report.csv and decisions.jsonl`);
}
