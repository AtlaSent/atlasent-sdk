/**
 * Acceptance run for the refund execution contract (atlasent-api#4656),
 * against Stripe TEST mode and a real AtlaSent org.
 *
 *   STRIPE_SETUP_KEY=sk_test_... STRIPE_SECRET_KEY=rk_test_... \
 *   ATLASENT_API_KEY=... ATLASENT_BASE_URL=... ATLASENT_ENVIRONMENT=test \
 *   STRIPE_ACCEPTANCE_CONFIRM=test-mode npm run acceptance -- [--out acceptance-out]
 *
 * Each case creates its own fresh test-mode payment (pm_card_visa, no real
 * money), labelled with `metadata.atlasent_acceptance_run`. Nothing is
 * deleted; test-mode objects stay as evidence. Writes `<out>/report.json` and
 * `<out>/ledger.json`.
 *
 * Verdicts are what was observed, never inferred:
 *   pass     the case's contract held
 *   fail     it did not (a defect)
 *   blocked  a precondition was not met, typically the org's policy did not
 *            allow the refund, so the contract could not be exercised.
 *            Blocked is never counted as pass.
 *
 * Two cases need a submission whose outcome is unknown. They wrap the real
 * Stripe client: one loses the response after Stripe created the refund, the
 * other fails before anything is sent. That injected fault is the only
 * simulation; every refund, readback and decision is real.
 *
 * This proves the adapter's contract on one Stripe test account and one
 * AtlaSent environment. It is not provider-wide, production or customer
 * acceptance, and it covers none of the business-source controls (order
 * ownership, returns, allocation, budgets).
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";
import { AtlaSentClient } from "@atlasent/sdk";
import type { DeliveryFacts } from "./facts.js";
import { staticDeliveryFacts } from "./facts.js";
import {
  guardedStripeRefund,
  reconcileStripeRefund,
  type StripeRefundGuardOptions,
  type StripeRefundResult,
} from "./guard.js";
import { JsonFileLedger, type PermitLedger } from "./ledger.js";
import { assertTestSetupKey, paymentIntentForm } from "./seed.js";
import { createStripeClient, StripeApiError, type StripeApi, type StripeRefund } from "./stripe.js";

export const ACCEPTANCE_SCHEMA = "atlasent.refund_execution_acceptance.v1" as const;

export type CaseVerdict = "pass" | "fail" | "blocked";

export interface AcceptanceCase {
  id: string;
  title: string;
  verdict: CaseVerdict;
  detail: string;
  evidence: Record<string, unknown>;
}

export interface AcceptanceDeps {
  stripe: StripeApi;
  atlasent: AtlaSentClient;
  ledger: PermitLedger;
  /** Creates one fresh, succeeded test payment and registers its order as delivered. */
  newPayment(caseId: string, capturedCents: number): Promise<string>;
  options: Omit<StripeRefundGuardOptions, "ledger" | "delivery"> & { delivery: StripeRefundGuardOptions["delivery"] };
  runId: string;
}

const CAPTURED = 3000;
const REFUND = 1500;

const brief = (r: StripeRefundResult) =>
  r.refunded
    ? { refunded: true, completion: r.completion, refund_id: r.refund.id, gate_ref: r.gateRef }
    : { refunded: false, decision: r.decision, reason: r.reason, gate_ref: r.gateRef, ...(r.denyCode ? { deny_code: r.denyCode } : {}) };

/**
 * A refund the policy did not allow, so the contract under test was not exercised.
 * verify_failed is NOT here: policy allowed, and verification is part of the contract.
 */
function notAllowed(r: StripeRefundResult): boolean {
  return !r.refunded && ["deny", "hold", "escalate"].includes(r.decision);
}

/** Stripe accepted the refund (requires_action included); completion is a separate fact. */
const ACCEPTED = new Set(["succeeded", "pending", "requires_action"]);

async function tagged(stripe: StripeApi, pi: string, gateRef: string): Promise<StripeRefund[]> {
  return (await stripe.listRefunds(pi)).filter((r) => r.metadata?.atlasent_gate_ref === gateRef);
}

/** Wraps the real client so the next createRefund loses its response, after or before Stripe acts. */
function faulty(stripe: StripeApi, mode: "after_create" | "before_send"): StripeApi {
  let armed = true;
  return {
    getPaymentIntent: (id) => stripe.getPaymentIntent(id),
    listRefunds: (id) => stripe.listRefunds(id),
    async createRefund(input, key) {
      if (!armed) return stripe.createRefund(input, key);
      armed = false;
      if (mode === "after_create") await stripe.createRefund(input, key);
      throw new Error(`injected fault: response lost ${mode === "after_create" ? "after Stripe created the refund" : "before the request was sent"}`);
    },
  };
}

export async function runAcceptance(deps: AcceptanceDeps): Promise<AcceptanceCase[]> {
  const opts: StripeRefundGuardOptions = { ...deps.options, ledger: deps.ledger };
  const out: AcceptanceCase[] = [];
  const add = (c: AcceptanceCase) => out.push(c);
  const brid = (c: string) => `acc-${deps.runId}:${c}`;
  const guard = (stripe: StripeApi, pi: string, amount: number, id?: string) =>
    guardedStripeRefund(stripe, deps.atlasent, { paymentIntentId: pi, amountCents: amount, ...(id ? { businessRequestId: id } : {}) }, opts);

  // A1, A2, A3 share one payment and one business request.
  const pi1 = await deps.newPayment("a1", CAPTURED);
  const r1 = await guard(deps.stripe, pi1, REFUND, brid("a1"));
  if (notAllowed(r1)) {
    for (const [id, title] of [["A1", "allowed refund, read back"], ["A2", "retry is answered from the ledger"], ["A3", "business id reused with another amount"]]) {
      add({ id: id as string, title: title as string, verdict: "blocked", detail: "the org's policy did not allow the refund, so this case could not run", evidence: { payment_intent: pi1, first: brief(r1) } });
    }
  } else {
    const rb = r1.refunded ? await reconcileStripeRefund(deps.stripe, r1.gateRef, opts) : null;
    const okA1 = r1.refunded && rb !== null && ACCEPTED.has(rb.state) && rb.refundId === r1.refund.id;
    add({
      id: "A1",
      title: "allowed refund, read back",
      verdict: okA1 ? "pass" : "fail",
      detail: okA1 ? `Stripe ${r1.refunded ? r1.completion : ""}; readback ${rb?.state}` : "the refund was not issued and read back as one matching refund",
      evidence: { payment_intent: pi1, result: brief(r1), readback: rb },
    });

    const r2 = await guard(deps.stripe, pi1, REFUND, brid("a1"));
    const t2 = await tagged(deps.stripe, pi1, r1.gateRef);
    const okA2 = !r2.refunded && r2.decision === "duplicate_request" && t2.length === 1;
    add({ id: "A2", title: "retry is answered from the ledger", verdict: okA2 ? "pass" : "fail", detail: `decision ${r2.refunded ? "refunded" : r2.decision}; ${t2.length} refund(s) carry the gate reference`, evidence: { result: brief(r2), tagged_refunds: t2.map((r) => r.id) } });

    const r3 = await guard(deps.stripe, pi1, REFUND - 100, brid("a1"));
    const t3 = await tagged(deps.stripe, pi1, r1.gateRef);
    const okA3 = !r3.refunded && r3.decision === "invalid_request" && t3.length === 1;
    add({ id: "A3", title: "business id reused with another amount", verdict: okA3 ? "pass" : "fail", detail: `decision ${r3.refunded ? "refunded" : r3.decision}`, evidence: { result: brief(r3) } });
  }

  // A4: two simultaneous refunds on one payment.
  const pi4 = await deps.newPayment("a4", CAPTURED);
  const [x, y] = await Promise.all([guard(deps.stripe, pi4, 1000, brid("a4-x")), guard(deps.stripe, pi4, 1000, brid("a4-y"))]);
  const inProgress = [x, y].filter((r) => !r.refunded && r.decision === "in_progress").length;
  const refundsA4 = (await deps.stripe.listRefunds(pi4)).length;
  // Blocked only when policy refused the request that ran; two refusals as
  // in_progress mean nothing ran at all, which is a defect, not a precondition.
  if ([x, y].some(notAllowed) && [x, y].every((r) => notAllowed(r) || (!r.refunded && r.decision === "in_progress"))) {
    add({ id: "A4", title: "simultaneous refunds on one payment", verdict: "blocked", detail: "the request that ran was not allowed by policy", evidence: { payment_intent: pi4, results: [brief(x), brief(y)] } });
  } else {
    const okA4 = inProgress === 1 && refundsA4 === 1;
    add({ id: "A4", title: "simultaneous refunds on one payment", verdict: okA4 ? "pass" : "fail", detail: `${inProgress} refused in_progress; ${refundsA4} refund(s) on the payment`, evidence: { payment_intent: pi4, results: [brief(x), brief(y)] } });
  }

  // A5: Stripe created the refund, the response was lost.
  const pi5 = await deps.newPayment("a5", CAPTURED);
  const r5 = await guard(faulty(deps.stripe, "after_create"), pi5, REFUND, brid("a5"));
  if (notAllowed(r5)) {
    add({ id: "A5", title: "lost response stays unconfirmed, then reconciles", verdict: "blocked", detail: "not allowed by policy", evidence: { payment_intent: pi5, result: brief(r5) } });
  } else {
    const other = await guard(deps.stripe, pi5, 500, brid("a5-other"));
    const rb5 = await reconcileStripeRefund(deps.stripe, r5.gateRef, opts);
    const again = await guard(deps.stripe, pi5, REFUND, brid("a5"));
    const t5 = await tagged(deps.stripe, pi5, r5.gateRef);
    const okA5 =
      !r5.refunded && r5.decision === "unconfirmed" &&
      !other.refunded && other.decision === "in_progress" &&
      ACCEPTED.has(rb5.state) &&
      !again.refunded && again.decision === "duplicate_request" &&
      t5.length === 1;
    add({
      id: "A5",
      title: "lost response stays unconfirmed, then reconciles",
      verdict: okA5 ? "pass" : "fail",
      detail: `first ${r5.refunded ? "refunded" : r5.decision}; other refund ${other.refunded ? "refunded" : other.decision}; readback ${rb5.state}; retry ${again.refunded ? "refunded" : again.decision}; ${t5.length} tagged refund(s)`,
      evidence: { payment_intent: pi5, first: brief(r5), other: brief(other), readback: rb5, retry: brief(again), tagged_refunds: t5.map((r) => r.id) },
    });
  }

  // A6: the request never reached Stripe; resubmitted with the same key.
  const pi6 = await deps.newPayment("a6", CAPTURED);
  const r6 = await guard(faulty(deps.stripe, "before_send"), pi6, REFUND, brid("a6"));
  if (notAllowed(r6)) {
    add({ id: "A6", title: "unsent request resubmits under the same key", verdict: "blocked", detail: "not allowed by policy", evidence: { payment_intent: pi6, result: brief(r6) } });
  } else {
    const plain = await reconcileStripeRefund(deps.stripe, r6.gateRef, opts);
    const resent = await reconcileStripeRefund(deps.stripe, r6.gateRef, opts, { resubmit: true });
    const t6 = await tagged(deps.stripe, pi6, r6.gateRef);
    const okA6 =
      !r6.refunded && r6.decision === "unconfirmed" &&
      plain.state === "unconfirmed" &&
      resent.resubmitted === true && ACCEPTED.has(resent.state) &&
      t6.length === 1;
    add({
      id: "A6",
      title: "unsent request resubmits under the same key",
      verdict: okA6 ? "pass" : "fail",
      detail: `first ${r6.refunded ? "refunded" : r6.decision}; readback ${plain.state}; resubmit ${resent.state}; ${t6.length} tagged refund(s)`,
      evidence: { payment_intent: pi6, first: brief(r6), readback: plain, resubmit: resent, tagged_refunds: t6.map((r) => r.id) },
    });
  }
  return out;
}

export function summarize(cases: AcceptanceCase[]) {
  const n = (v: CaseVerdict) => cases.filter((c) => c.verdict === v).length;
  return { pass: n("pass"), fail: n("fail"), blocked: n("blocked"), total: cases.length };
}

/** Creates one succeeded test PaymentIntent through the setup key. */
async function createTestPayment(setupKey: string, runId: string, caseId: string, cents: number, orderRef: string): Promise<string> {
  const form = paymentIntentForm({ orderRef, item: `acceptance ${caseId}`, amountCents: cents, delivery: "delivered", daysAgo: 1, refundCents: 0, expect: "" })
    + `&metadata%5Batlasent_acceptance_run%5D=${encodeURIComponent(runId)}`;
  const res = await fetch("https://api.stripe.com/v1/payment_intents", {
    method: "POST",
    headers: { authorization: `Bearer ${setupKey}`, "content-type": "application/x-www-form-urlencoded", "idempotency-key": `atlasent-acceptance-${runId}-${caseId}` },
    body: form,
    signal: AbortSignal.timeout(15_000),
  });
  const body = (await res.json().catch(() => null)) as { id?: string; status?: string; error?: { message?: string } } | null;
  if (!res.ok || !body?.id) throw new StripeApiError(`creating the ${caseId} payment failed: HTTP ${res.status}${body?.error?.message ? `: ${body.error.message}` : ""}`, res.status);
  if (body.status !== "succeeded") throw new Error(`the ${caseId} payment ${body.id} is ${body.status}, not succeeded`);
  return body.id;
}

async function main(): Promise<number> {
  const { values } = parseArgs({ options: { out: { type: "string" } } });
  const need = (k: string) => {
    const v = process.env[k];
    if (!v) throw new Error(`${k} is required`);
    return v;
  };
  const setupKey = need("STRIPE_SETUP_KEY");
  assertTestSetupKey(setupKey);
  const secretKey = need("STRIPE_SECRET_KEY");
  if (!/^(sk|rk)_test_/.test(secretKey)) throw new Error("STRIPE_SECRET_KEY must be a test-mode key");
  if (process.env.STRIPE_ACCEPTANCE_CONFIRM !== "test-mode") throw new Error("Refusing to run without STRIPE_ACCEPTANCE_CONFIRM=test-mode");
  const apiKey = need("ATLASENT_API_KEY");
  const baseUrl = process.env.ATLASENT_BASE_URL;
  const environment = need("ATLASENT_ENVIRONMENT");

  const startedAt = new Date();
  const runId = process.env.ACCEPTANCE_RUN_ID ?? startedAt.toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  const outDir = values.out ?? "acceptance-out";
  mkdirSync(outDir, { recursive: true });
  const delivered: Record<string, DeliveryFacts> = {};
  const deps: AcceptanceDeps = {
    stripe: createStripeClient({ secretKey }),
    atlasent: new AtlaSentClient({ apiKey, ...(baseUrl ? { baseUrl } : {}) }),
    ledger: new JsonFileLedger(join(outDir, "ledger.json")),
    runId,
    async newPayment(caseId, cents) {
      const orderRef = `ACC-${runId}-${caseId}`;
      delivered[orderRef] = { order_status: "delivered", delivered_at: new Date(Date.now() - 86_400_000).toISOString() };
      return createTestPayment(setupKey, runId, caseId, cents, orderRef);
    },
    options: {
      actor: process.env.ATLASENT_ACTOR ?? "acceptance:refund-execution",
      environment,
      account: process.env.STRIPE_ACCOUNT_LABEL ?? "test-account",
      delivery: staticDeliveryFacts(delivered),
    },
  };
  const cases = await runAcceptance(deps);
  const report = {
    schema: ACCEPTANCE_SCHEMA,
    truth_label: "stripe_test_mode_synthetic",
    run_id: runId,
    started_at: startedAt.toISOString(),
    finished_at: new Date().toISOString(),
    stripe_account_label: deps.options.account,
    atlasent_base_url: baseUrl ?? "(SDK default)",
    atlasent_environment: environment,
    action_type: deps.options.actionType ?? "finance.payment.authorize",
    adapter_revision: process.env.GITHUB_SHA ?? process.env.ADAPTER_REVISION ?? "unrecorded",
    summary: summarize(cases),
    cases,
    not_covered: "order/customer ownership, return evidence, allocation, cumulative budgets, accounting, webhook delivery, production",
  };
  writeFileSync(join(outDir, "report.json"), JSON.stringify(report, null, 2));
  for (const c of cases) console.log(`${c.verdict.toUpperCase().padEnd(7)} ${c.id} ${c.title}: ${c.detail}`);
  console.log(`\n${JSON.stringify(report.summary)}  report: ${join(outDir, "report.json")}`);
  return report.summary.fail > 0 ? 1 : report.summary.blocked > 0 ? 3 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(err instanceof Error ? err.message : err);
      process.exit(2);
    },
  );
}
