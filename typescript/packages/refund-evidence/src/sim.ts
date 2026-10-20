/**
 * Simulated pieces for the one-command demo. Everything here is labelled as
 * simulated in the report it feeds.
 *
 *   - `simulatedRuntime`: a LOCAL STAND-IN for the AtlaSent runtime. It
 *     applies the demo refund policy (atlasent-api
 *     `examples/fake-store-refunds/policy.json`, re-stated) and the permit
 *     binding, behind the real `AtlaSentClient`. Its audit references are
 *     placeholders. Set ATLASENT_API_KEY to use the real runtime instead.
 *     Like the runtime, it opens an approval request for every escalation;
 *     `decide` plays the manager deciding it in the AtlaSent console.
 *   - `SimShopify` / `SimStripe`: in-memory stores implementing the same
 *     interfaces the gates call, plus a way to refund AROUND the gate (staff
 *     in the Shopify admin, a teammate in the Stripe Dashboard) so the alarm
 *     has something to catch.
 */

import { createHash } from "node:crypto";
import { AtlaSentClient } from "@atlasent/sdk";
import type { CreatedRefund, GetOrderOptions, RefundCreateInput, ShopifyAdmin, ShopifyOrder } from "../../shopify/src/admin.js";
import type { RefundWebhookPayload } from "../../shopify/src/webhook.js";
import type { CreateRefundInput, StripeApi, StripePaymentIntent, StripeRefund } from "../../stripe/src/stripe.js";
import type { ApprovalsApi } from "../../shopify/src/approvals.js";

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
const DAY_MS = 86_400_000;

function demoPolicy(ctx: Record<string, unknown>): { decision: string; deny_code?: string; deny_reason?: string } {
  const amount = ctx.amount_cents;
  if (typeof amount !== "number" || !(amount > 0)) return { decision: "deny", deny_code: "INVALID_REFUND_AMOUNT", deny_reason: "A refund must carry a positive amount in cents." };
  if (ctx.order_status !== "delivered") return { decision: "deny", deny_code: "ORDER_NOT_DELIVERED", deny_reason: "Refunds are only issued on delivered orders." };
  const days = ctx.days_since_delivery;
  if (typeof days !== "number" || !(days >= 0)) return { decision: "deny", deny_code: "RETURN_WINDOW_UNKNOWN", deny_reason: "The return window cannot be checked." };
  if (days > 30) return { decision: "deny", deny_code: "RETURN_WINDOW_EXPIRED", deny_reason: "Refunds are only issued within 30 days of delivery." };
  if (amount < 5000) return { decision: "allow" };
  return { decision: "escalate", deny_code: "MANAGER_APPROVAL_REQUIRED", deny_reason: "Refunds of $50.00 or more need a store manager's approval." };
}

export interface SimulatedRuntime {
  /** The real AtlaSentClient, over the stand-in. */
  client: AtlaSentClient;
  /** The approval-request reads and claims the gates' resume path makes. */
  approvals: ApprovalsApi;
  /** The manager's decision in the console: "approved" or "denied". */
  decide(approvalRequestId: string, status: "approved" | "denied"): void;
}

/** The real AtlaSentClient over a local stand-in runtime. */
export function simulatedRuntime(): AtlaSentClient {
  return createSimulatedRuntime().client;
}

export function createSimulatedRuntime(): SimulatedRuntime {
  const permits = new Map<string, { bound: string; consumed: boolean }>();
  const approvalRows = new Map<string, { status: string; bound: string; claimed: boolean }>();
  let seq = 0;
  const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
    const path = new URL(String(url)).pathname;
    const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
    let out: unknown;
    if (path.endsWith("/v1-evaluate")) {
      const d = demoPolicy((body.context ?? {}) as Record<string, unknown>);
      const audit = `sim-audit-${sha256(JSON.stringify(body)).slice(0, 16)}`;
      if (d.decision === "escalate") {
        const id = `sim-approval-${++seq}`;
        const ep = body.execution_payload_hash;
        approvalRows.set(id, { status: "pending", bound: typeof ep === "string" ? ep.toLowerCase() : "", claimed: false });
        out = { ...d, audit_hash: audit, approval_request_id: id };
      } else if (d.decision !== "allow") out = { ...d, audit_hash: audit };
      else {
        const ep = body.execution_payload_hash;
        const token = `pt.sim.${++seq}`;
        permits.set(token, { bound: typeof ep === "string" ? ep.toLowerCase() : "", consumed: false });
        out = { decision: "allow", permit_token: token, audit_hash: audit };
      }
    } else if (path.endsWith("/v1-verify-permit")) {
      const p = permits.get(String(body.permit_token));
      if (!p || p.consumed || (body.payload_hash ?? body.execution_hash) !== p.bound) out = { valid: false, outcome: "deny" };
      else {
        p.consumed = true;
        out = { valid: true, outcome: "allow", consumed: true };
      }
    } else return new Response("{}", { status: 404 });
    return new Response(JSON.stringify(out), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  const client = new AtlaSentClient({ apiKey: "ask_test_simulated", fetch: fetchImpl, retryPolicy: { maxAttempts: 1 } });
  const approvals: ApprovalsApi = {
    async getStatus(id) {
      const row = approvalRows.get(id);
      return row ? { found: true, status: row.status } : { found: false };
    },
    async claimPermit(id) {
      const row = approvalRows.get(id);
      if (!row || row.status !== "approved" || row.claimed) return { claimed: false, failure: "not_claimable" };
      row.claimed = true;
      const token = `pt.sim.${++seq}`;
      permits.set(token, { bound: row.bound, consumed: false });
      return { claimed: true, permitToken: token, executionHashExpected: row.bound };
    },
  };
  const decide = (id: string, status: "approved" | "denied") => {
    const row = approvalRows.get(id);
    if (!row) throw new Error(`no approval request ${id}`);
    row.status = status;
  };
  return { client, approvals, decide };
}

export interface SimOrderSpec {
  id: number;
  email: string;
  paid: string;
  delivery: "delivered" | "in_transit";
  daysAgo: number;
}

export class SimShopify implements ShopifyAdmin {
  readonly orders = new Map<string, ShopifyOrder>();
  readonly webhooks: RefundWebhookPayload[] = [];
  private refundSeq = 0;

  constructor(specs: SimOrderSpec[], now: Date) {
    for (const s of specs) {
      const gid = `gid://shopify/Order/${s.id}`;
      this.orders.set(gid, {
        id: gid,
        name: `#PPS-${s.id}`,
        email: s.email,
        currencyCode: "USD",
        cancelledAt: null,
        fulfillments: [
          {
            id: `gid://shopify/Fulfillment/${s.id}`,
            status: "SUCCESS",
            displayStatus: s.delivery === "delivered" ? "DELIVERED" : "IN_TRANSIT",
            deliveredAt: s.delivery === "delivered" ? new Date(now.getTime() - s.daysAgo * DAY_MS).toISOString() : null,
          },
        ],
        transactions: [
          { id: `gid://shopify/OrderTransaction/${s.id}1`, kind: "SALE", status: "SUCCESS", gateway: "manual", amountSet: { shopMoney: { amount: s.paid, currencyCode: "USD" } }, parentTransaction: null },
        ],
      });
    }
  }

  async getOrder(orderId: string, options?: GetOrderOptions): Promise<ShopifyOrder | null> {
    const o = this.orders.get(orderId.startsWith("gid://") ? orderId : `gid://shopify/Order/${orderId}`);
    if (!o) return null;
    const copy = JSON.parse(JSON.stringify(o)) as ShopifyOrder;
    if (options?.includeEmail !== true) delete copy.email;
    return copy;
  }

  private record(orderId: string, amount: string, note: string): { id: string; payload: RefundWebhookPayload } {
    const o = this.orders.get(orderId)!;
    const id = String(9000 + ++this.refundSeq);
    o.transactions.push({ id: `gid://shopify/OrderTransaction/r${id}`, kind: "REFUND", status: "SUCCESS", gateway: "manual", amountSet: { shopMoney: { amount, currencyCode: "USD" } }, parentTransaction: null });
    const payload: RefundWebhookPayload = { id, order_id: orderId.replace(/^gid:\/\/shopify\/Order\//, ""), note, transactions: [{ kind: "refund", status: "success", amount }] };
    this.webhooks.push(payload);
    return { id, payload };
  }

  async createRefund(input: RefundCreateInput): Promise<CreatedRefund> {
    const t = input.transactions[0]!;
    const { id } = this.record(input.orderId, t.amount, input.note);
    return { id: `gid://shopify/Refund/${id}`, createdAt: new Date().toISOString(), totalRefunded: { amount: t.amount, currencyCode: "USD" } };
  }

  /** A staff member refunding in the Shopify admin, around the gate. */
  adminRefund(orderId: string, amount: string, note: string): RefundWebhookPayload {
    return this.record(orderId, amount, note).payload;
  }
}

export class SimStripe implements StripeApi {
  readonly pis = new Map<string, StripePaymentIntent>();
  readonly events: StripeRefund[] = [];
  private byKey = new Map<string, StripeRefund>();

  constructor(specs: { id: string; orderRef: string; captured: number }[], now: Date) {
    for (const s of specs) {
      this.pis.set(s.id, {
        id: s.id,
        status: "succeeded",
        currency: "usd",
        metadata: { order_id: s.orderRef },
        latest_charge: { id: `ch_${s.id.slice(3)}`, status: "succeeded", currency: "usd", amount_captured: s.captured, amount_refunded: 0, disputed: false, created: Math.floor(now.getTime() / 1000) },
      });
    }
  }

  async getPaymentIntent(id: string): Promise<StripePaymentIntent | null> {
    const p = this.pis.get(id);
    return p ? (JSON.parse(JSON.stringify(p)) as StripePaymentIntent) : null;
  }

  private record(pi: string, amount: number, metadata: Record<string, string>): StripeRefund {
    const p = this.pis.get(pi)!;
    p.latest_charge!.amount_refunded += amount;
    const refund: StripeRefund = { id: `re_sim_${this.events.length + 1}`, status: "succeeded", amount, currency: "usd", charge: p.latest_charge!.id, payment_intent: pi, metadata };
    this.events.push(refund);
    return refund;
  }

  async createRefund(input: CreateRefundInput, key: string): Promise<StripeRefund> {
    const prior = this.byKey.get(key);
    if (prior) return prior;
    const r = this.record(input.payment_intent, input.amount, input.metadata);
    this.byKey.set(key, r);
    return r;
  }

  /** A teammate refunding in the Stripe Dashboard, around the gate. */
  dashboardRefund(pi: string, amount: number): StripeRefund {
    return this.record(pi, amount, {});
  }
}
