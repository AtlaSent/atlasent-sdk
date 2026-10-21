/**
 * Creates the demo payments in a Stripe account's TEST mode, plus the
 * delivery file that stands in for the store's order system.
 *
 *   STRIPE_SETUP_KEY=sk_test_... STRIPE_SEED_CONFIRM=test-mode \
 *   npm run seed-test-payments -- [--dry-run] [--out stripe-demo]
 *
 * Each payment is a PaymentIntent confirmed with Stripe's test card
 * (`pm_card_visa`), so it succeeds and moves no real money. Its
 * `metadata.order_id` links it to an order in the delivery file, exactly as a
 * store's checkout would. Writes `<out>/delivery.json` and
 * `<out>/payments.json`, then prints the commands for each scenario.
 *
 * Use a separate SETUP key here, not the gate's restricted key: creating
 * payments needs PaymentIntent write access the gate must never have. Only
 * `sk_test_` keys are accepted. Not yet run against a live Stripe account:
 * check the PaymentIntent fields against your account's API version.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";
import { formEncode } from "./stripe.js";
import type { DeliveryFacts } from "./facts.js";

export interface SeedScenario {
  orderRef: string;
  item: string;
  amountCents: number;
  delivery: "delivered" | "not_delivered";
  daysAgo: number;
  /** The refund to request, and what the demo policy should decide. */
  refundCents: number;
  expect: string;
}

export const SEED_SCENARIOS: SeedScenario[] = [
  { orderRef: "PPS-S101", item: "Rope chew toy", amountCents: 3499, delivery: "delivered", daysAgo: 5, refundCents: 1899, expect: "refunded" },
  { orderRef: "PPS-S102", item: "Cat tree, large", amountCents: 12900, delivery: "delivered", daysAgo: 3, refundCents: 7200, expect: "manager (approve it)" },
  { orderRef: "PPS-S103", item: "Heated dog bed", amountCents: 8500, delivery: "delivered", daysAgo: 2, refundCents: 8500, expect: "manager (decline it)" },
  { orderRef: "PPS-S104", item: "Bird seed, 2kg", amountCents: 2450, delivery: "not_delivered", daysAgo: 0, refundCents: 1200, expect: "denied: not delivered" },
  { orderRef: "PPS-S105", item: "Aquarium filter", amountCents: 4200, delivery: "delivered", daysAgo: 45, refundCents: 2500, expect: "denied: past 30 days" },
];

const DAY_MS = 86_400_000;

export function deliveryFile(scenarios: SeedScenario[], now: Date): Record<string, DeliveryFacts> {
  return Object.fromEntries(
    scenarios.map((s) => [
      s.orderRef,
      s.delivery === "delivered"
        ? { order_status: "delivered", delivered_at: new Date(now.getTime() - s.daysAgo * DAY_MS).toISOString() }
        : { order_status: "not_delivered" },
    ]),
  );
}

/** The form body for one test PaymentIntent. */
export function paymentIntentForm(s: SeedScenario): string {
  return formEncode({
    amount: s.amountCents,
    currency: "usd",
    payment_method: "pm_card_visa",
    confirm: true,
    description: `AtlaSent refund demo: ${s.item}`,
    automatic_payment_methods: { enabled: true, allow_redirects: "never" },
    metadata: { order_id: s.orderRef, atlasent_demo: "refund-gate" },
  });
}

export function assertTestSetupKey(key: string): void {
  if (!key.startsWith("sk_test_")) {
    throw new Error("STRIPE_SETUP_KEY must be a test-mode secret key (sk_test_...); live keys and restricted keys are refused");
  }
}

export interface SeededPayment {
  orderRef: string;
  paymentIntent: string;
  status: string;
  refundCents: number;
  expect: string;
}

export async function seedTestPayments(
  doFetch: typeof fetch,
  setupKey: string,
  scenarios: SeedScenario[],
  opts: { runId: string; baseUrl?: string },
): Promise<SeededPayment[]> {
  assertTestSetupKey(setupKey);
  const base = (opts.baseUrl ?? "https://api.stripe.com").replace(/\/$/, "");
  const out: SeededPayment[] = [];
  for (const s of scenarios) {
    const res = await doFetch(`${base}/v1/payment_intents`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${setupKey}`,
        "content-type": "application/x-www-form-urlencoded",
        // A re-run with the same run id returns the same payments instead of new ones.
        "idempotency-key": `atlasent-refund-demo-${opts.runId}-${s.orderRef}`,
      },
      body: paymentIntentForm(s),
      signal: AbortSignal.timeout(15_000),
    });
    const body = (await res.json().catch(() => null)) as { id?: string; status?: string; error?: { message?: string } } | null;
    if (!res.ok || !body?.id) {
      throw new Error(`creating ${s.orderRef} failed: HTTP ${res.status}${body?.error?.message ? `: ${body.error.message}` : ""}`);
    }
    if (body.status !== "succeeded") throw new Error(`${s.orderRef} (${body.id}) is ${body.status}, not succeeded; the gate refuses unsucceeded payments`);
    out.push({ orderRef: s.orderRef, paymentIntent: body.id, status: body.status, refundCents: s.refundCents, expect: s.expect });
  }
  return out;
}

export function runbook(payments: SeededPayment[], outDir: string): string {
  const money = (c: number) => (c / 100).toFixed(2);
  const lines = [
    `export DELIVERY_FACTS_FILE=${join(outDir, "delivery.json")} LEDGER_PATH=${join(outDir, "ledger.json")}`,
    "# with STRIPE_SECRET_KEY set to the gate's RESTRICTED test key (rk_test_...), not the setup key",
    "",
  ];
  for (const p of payments) {
    lines.push(`npm run refund -- refund --payment ${p.paymentIntent} --amount ${money(p.refundCents)} --reason "demo ${p.orderRef}"   # expect: ${p.expect}`);
  }
  lines.push("", "# after approving one escalation and declining the other in the AtlaSent console:", "npm run refund -- resume --approval <approval_request_id>");
  return lines.join("\n");
}

async function main(): Promise<number> {
  const { values } = parseArgs({ options: { "dry-run": { type: "boolean" }, out: { type: "string" } } });
  const outDir = values.out ?? "stripe-demo";
  if (values["dry-run"]) {
    console.log("Would create these test-mode payments (pm_card_visa, no real money):");
    for (const s of SEED_SCENARIOS) console.log(`  ${s.orderRef}  $${(s.amountCents / 100).toFixed(2)}  ${s.item}; then refund $${(s.refundCents / 100).toFixed(2)} → ${s.expect}`);
    console.log(`and write ${join(outDir, "delivery.json")} and ${join(outDir, "payments.json")}.`);
    return 0;
  }
  const key = process.env.STRIPE_SETUP_KEY;
  if (!key) {
    console.error("STRIPE_SETUP_KEY is required (a sk_test_ key, separate from the gate's restricted key)");
    return 2;
  }
  assertTestSetupKey(key);
  if (process.env.STRIPE_SEED_CONFIRM !== "test-mode") {
    console.error("Refusing to create payments without STRIPE_SEED_CONFIRM=test-mode");
    return 2;
  }
  const now = new Date();
  const runId = process.env.STRIPE_SEED_RUN_ID ?? now.toISOString().slice(0, 10);
  const payments = await seedTestPayments(fetch, key, SEED_SCENARIOS, { runId });
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "delivery.json"), JSON.stringify(deliveryFile(SEED_SCENARIOS, now), null, 2));
  writeFileSync(join(outDir, "payments.json"), JSON.stringify(payments, null, 2));
  console.log(`Created ${payments.length} test-mode payments:\n`);
  for (const p of payments) console.log(`  ${p.orderRef}  ${p.paymentIntent}  ${p.status}`);
  console.log(`\nNext:\n\n${runbook(payments, outDir)}`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(err instanceof Error ? err.message : err);
      process.exit(1);
    },
  );
}
