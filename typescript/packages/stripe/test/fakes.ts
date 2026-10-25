/**
 * Fakes shared by the tests.
 *
 * `fakeRuntime` drives the REAL AtlaSentClient over a fake fetch that applies
 * the demo refund policy (atlasent-api `examples/fake-store-refunds/policy.json`,
 * re-stated here) and the runtime's permit binding. It is the same fake the
 * @atlasent/shopify tests use.
 *
 * `FakeStripe` holds PaymentIntents in memory, records every refund, and
 * honours Idempotency-Key the way Stripe does: a repeated key returns the
 * first refund.
 */

import { createHash } from "node:crypto";
import { AtlaSentClient } from "@atlasent/sdk";
import { StripeApiError, type CreateRefundInput, type StripeApi, type StripePaymentIntent, type StripeRefund } from "../src/stripe.js";
import type { DeliveryFacts } from "../src/facts.js";
import type { ApprovalClaim, ApprovalsApi, ApprovalStatus } from "../src/approvals.js";

export const NOW = new Date("2026-10-20T12:00:00Z");
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

export interface RuntimeOptions {
  evaluateThrows?: boolean;
  verifyThrows?: boolean;
  /** `null` omits the field from a successful verify. */
  consumed?: boolean | null;
  verifyValid?: boolean;
  forceDecision?: string;
  /** Runs after verify answers, before the guard continues. */
  afterVerify?: () => void;
}

export function demoPolicy(ctx: Record<string, unknown>): { decision: string; deny_code?: string; deny_reason?: string } {
  const amount = ctx.amount_cents;
  if (typeof amount !== "number" || !(amount > 0)) return { decision: "deny", deny_code: "INVALID_REFUND_AMOUNT", deny_reason: "bad amount" };
  if (ctx.order_status !== "delivered") return { decision: "deny", deny_code: "ORDER_NOT_DELIVERED", deny_reason: "Condition 1: order not delivered" };
  const days = ctx.days_since_delivery;
  if (typeof days !== "number" || !(days >= 0)) return { decision: "deny", deny_code: "RETURN_WINDOW_UNKNOWN", deny_reason: "window unknown" };
  if (days > 30) return { decision: "deny", deny_code: "RETURN_WINDOW_EXPIRED", deny_reason: "Condition 2: more than 30 days" };
  if (amount < 5000) return { decision: "allow" };
  return { decision: "escalate", deny_code: "MANAGER_APPROVAL_REQUIRED", deny_reason: "Refunds of $50.00 or more need a manager" };
}

export function fakeRuntime(opts: RuntimeOptions = {}) {
  const evaluateBodies: Record<string, unknown>[] = [];
  const verifyBodies: Record<string, unknown>[] = [];
  const permits = new Map<string, { bound: string; consumed: boolean; actor: unknown; action: unknown; environment: unknown }>();
  /** Approval requests the runtime created for escalations. A test plays the person deciding them. */
  const approvalRows = new Map<string, { status: string; bound: string; claimed: boolean }>();
  let seq = 0;

  function evaluate(body: Record<string, unknown>) {
    evaluateBodies.push(body);
    if (opts.evaluateThrows) throw new Error("connect ECONNREFUSED");
    // Match the real runtime contract: top-level environment alone is not
    // sufficient, and conflicting environment claims must never authorize.
    const ctx = (body.context ?? {}) as Record<string, unknown>;
    if (typeof ctx.environment !== "string" || !ctx.environment.trim()) {
      throw new Error("context.environment is required");
    }
    if (ctx.environment !== body.environment) {
      throw new Error("context.environment does not match request environment");
    }
    if (opts.forceDecision) return { decision: opts.forceDecision, deny_reason: "forced" };
    const d = demoPolicy((body.context ?? {}) as Record<string, unknown>);
    if (d.decision !== "allow") {
      const n = ++seq;
      let approval = {};
      if (d.decision === "escalate") {
        const id = `apr-${n}`;
        const ep = body.execution_payload_hash;
        approvalRows.set(id, { status: "pending", bound: typeof ep === "string" ? ep.toLowerCase() : "", claimed: false });
        approval = { escalation_id: `esc-${n}`, approval_request_id: id };
      }
      return { ...d, audit_hash: `audit-${n}`, ...approval };
    }
    const ep = body.execution_payload_hash;
    const bound = typeof ep === "string" && /^[0-9a-f]{64}$/i.test(ep) ? ep.toLowerCase() : "sha256:" + sha256(JSON.stringify(body));
    const token = `pt.v3.fake-${++seq}`;
    permits.set(token, { bound, consumed: false, actor: body.actor_id, action: body.action_type, environment: body.environment });
    return { decision: "allow", permit_token: token, audit_hash: `audit-${seq}` };
  }

  function verify(body: Record<string, unknown>) {
    verifyBodies.push(body);
    if (opts.verifyThrows) throw new Error("socket hang up");
    const p = permits.get(String(body.permit_token));
    if (!p) return { valid: false, outcome: "deny", verify_error_code: "PERMIT_NOT_FOUND" };
    if (p.consumed) return { valid: false, outcome: "deny", verify_error_code: "PERMIT_ALREADY_USED" };
    if (body.actor_id !== p.actor) return { valid: false, outcome: "deny", verify_error_code: "ACTOR_MISMATCH" };
    if (body.action_type !== p.action) return { valid: false, outcome: "deny", verify_error_code: "ACTION_MISMATCH" };
    if (body.environment !== p.environment) return { valid: false, outcome: "deny", verify_error_code: "ENVIRONMENT_MISMATCH" };
    const presented = body.payload_hash ?? body.execution_hash;
    if (presented !== p.bound) return { valid: false, outcome: "deny", verify_error_code: "PAYLOAD_MISMATCH" };
    if (opts.verifyValid === false) return { valid: false, outcome: "deny", verify_error_code: "FORCED" };
    p.consumed = true;
    const consumed = opts.consumed === undefined ? true : opts.consumed;
    return { valid: true, outcome: "allow", ...(consumed === null ? {} : { consumed }) };
  }

  const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
    const path = new URL(String(url)).pathname;
    const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
    let out: unknown;
    if (path.endsWith("/v1-evaluate")) out = evaluate(body);
    else if (path.endsWith("/v1-verify-permit")) {
      out = verify(body);
      opts.afterVerify?.();
    } else return new Response(JSON.stringify({ error: "not_found" }), { status: 404 });
    return new Response(JSON.stringify(out), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;

  const client = new AtlaSentClient({ apiKey: "ask_test_fake", fetch: fetchImpl, retryPolicy: { maxAttempts: 1 } });

  const claims: string[] = [];
  /** Options to make the claim misbehave, for fail-closed tests. */
  const claimFaults: { boundTo?: string; failure?: string } = {};
  const approvals: ApprovalsApi = {
    async getStatus(id): Promise<ApprovalStatus> {
      const row = approvalRows.get(id);
      return row ? { found: true, status: row.status } : { found: false };
    },
    async claimPermit(id): Promise<ApprovalClaim> {
      claims.push(id);
      const row = approvalRows.get(id);
      if (claimFaults.failure) return { claimed: false, failure: claimFaults.failure };
      if (!row || row.status !== "approved" || row.claimed) return { claimed: false, failure: "not_claimable" };
      row.claimed = true;
      const token = `pt.v3.approved-${++seq}`;
      const bound = claimFaults.boundTo ?? row.bound;
      permits.set(token, { bound, consumed: false });
      return { claimed: true, permitToken: token, executionHashExpected: bound };
    },
  };
  /** A person deciding the approval in the AtlaSent console. */
  const decide = (id: string, status: string) => {
    const row = approvalRows.get(id);
    if (!row) throw new Error(`no approval ${id}`);
    row.status = status;
  };
  return { client, evaluateBodies, verifyBodies, permits, approvals, decide, claims, claimFaults, approvalRows };
}

const DAY_MS = 86_400_000;

export interface PaymentSpec {
  id: string;
  orderRef?: string | null;
  captured: number;
  refunded?: number;
  currency?: string;
  status?: string;
  disputed?: boolean;
}

export function makePaymentIntent(spec: PaymentSpec): StripePaymentIntent {
  return {
    id: spec.id,
    status: spec.status ?? "succeeded",
    currency: spec.currency ?? "usd",
    metadata: spec.orderRef === null ? {} : { order_id: spec.orderRef ?? `order-${spec.id}` },
    latest_charge: {
      id: `ch_${spec.id.slice(3)}`,
      status: spec.status ?? "succeeded",
      currency: spec.currency ?? "usd",
      amount_captured: spec.captured,
      amount_refunded: spec.refunded ?? 0,
      disputed: spec.disputed ?? false,
      created: Math.floor(NOW.getTime() / 1000) - 7 * 86_400,
    },
  };
}

export const delivered = (daysAgo: number): DeliveryFacts => ({
  order_status: "delivered",
  delivered_at: new Date(NOW.getTime() - daysAgo * DAY_MS).toISOString(),
});

export class FakeStripe implements StripeApi {
  pis = new Map<string, StripePaymentIntent>();
  refunds: { input: CreateRefundInput; key: string }[] = [];
  private byKey = new Map<string, StripeRefund>();
  reads = 0;
  existingRefunds: StripeRefund[] = [];
  async listRefunds(id: string): Promise<StripeRefund[]> {
    return structuredClone([...this.existingRefunds, ...this.byKey.values()].filter(r => r.payment_intent === id));
  }
  failGet = false;
  /** true: an uncertain transport error. A number: Stripe answered with that HTTP status. */
  failRefund: boolean | number = false;
  /** Create the refund, then lose the response (the timeout-after-commit case). */
  loseResponseAfterCreate = false;
  refundStatus = "succeeded";
  onRead?: (n: number, fake: FakeStripe) => void;

  constructor(pis: StripePaymentIntent[]) {
    for (const p of pis) this.pis.set(p.id, p);
  }

  async getPaymentIntent(id: string): Promise<StripePaymentIntent | null> {
    if (this.failGet) throw new Error("Stripe API HTTP 503");
    const p = this.pis.get(id) ?? null;
    this.reads++;
    const snap = p ? (JSON.parse(JSON.stringify(p)) as StripePaymentIntent) : null;
    this.onRead?.(this.reads, this);
    return snap;
  }

  async createRefund(input: CreateRefundInput, key: string): Promise<StripeRefund> {
    if (typeof this.failRefund === "number") throw new StripeApiError(`Stripe API HTTP ${this.failRefund}`, this.failRefund);
    if (this.failRefund) throw new Error("fetch failed: socket hang up");
    const prior = this.byKey.get(key);
    if (prior) return prior;
    this.refunds.push({ input: JSON.parse(JSON.stringify(input)), key });
    const pi = this.pis.get(input.payment_intent)!;
    pi.latest_charge!.amount_refunded += input.amount;
    const refund: StripeRefund = {
      id: `re_${this.refunds.length}`,
      status: this.refundStatus,
      amount: input.amount,
      currency: "usd",
      charge: pi.latest_charge!.id,
      payment_intent: pi.id,
      metadata: { ...input.metadata },
    };
    this.byKey.set(key, refund);
    if (this.loseResponseAfterCreate) throw new Error("The operation was aborted due to timeout");
    return refund;
  }
}

/** The five demo scenarios as Stripe payments, plus where each order stands. */
export function demoPayments() {
  return {
    pis: [
      makePaymentIntent({ id: "pi_1001", orderRef: "PPS-1001", captured: 3499 }),
      makePaymentIntent({ id: "pi_1002", orderRef: "PPS-1002", captured: 12900 }),
      makePaymentIntent({ id: "pi_1003", orderRef: "PPS-1003", captured: 2450 }),
      makePaymentIntent({ id: "pi_1004", orderRef: "PPS-1004", captured: 4200 }),
      makePaymentIntent({ id: "pi_1005", orderRef: "PPS-1005", captured: 1999 }),
    ],
    delivery: {
      "PPS-1001": delivered(5),
      "PPS-1002": delivered(3),
      "PPS-1003": { order_status: "not_delivered" },
      "PPS-1004": delivered(45),
      "PPS-1005": delivered(10),
    } as Record<string, DeliveryFacts>,
  };
}

