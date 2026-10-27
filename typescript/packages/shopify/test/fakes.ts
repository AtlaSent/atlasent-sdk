/**
 * Fakes shared by the tests.
 *
 * `fakeRuntime` drives the REAL AtlaSentClient over a fake fetch that applies
 * what the runtime does for this demo:
 *   - the refund policy from atlasent-api `examples/fake-store-refunds/policy.json`
 *     (re-stated here; that file and its own tests are the source of truth);
 *   - the permit binds top-level `execution_payload_hash` when it is bare hex,
 *     else a hash of the whole body;
 *   - verify compares the presented `execution_hash` and burns the permit.
 *
 * `FakeShopify` holds orders in memory and records every refundCreate.
 */

import { createHash } from "node:crypto";
import { AtlaSentClient } from "@atlasent/sdk";
import type { CreatedRefund, GetOrderOptions, RefundCreateInput, RefundReadback, ShopifyAdmin, ShopifyOrder } from "../src/admin.js";
import type { ApprovalClaim, ApprovalsApi, ApprovalStatus } from "../src/approvals.js";

export const NOW = new Date("2026-10-20T12:00:00Z");
const DAY = 86_400_000;
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
  type Binding = { actor: unknown; action: unknown; environment: unknown };
  const permits = new Map<string, Binding & { bound: string; consumed: boolean }>();
  /** Approval requests the runtime created for escalations. A test plays the person deciding them. */
  const approvalRows = new Map<string, Binding & { status: string; bound: string; claimed: boolean }>();
  let seq = 0;

  function evaluate(body: Record<string, unknown>) {
    evaluateBodies.push(body);
    if (typeof body.environment !== "string" || body.environment.length === 0 ||
        (body.context as Record<string, unknown>)?.environment !== body.environment) throw new Error("context.environment is required and must match");
    if (opts.evaluateThrows) throw new Error("connect ECONNREFUSED");
    if (opts.forceDecision) return { decision: opts.forceDecision, deny_reason: "forced" };
    const d = demoPolicy((body.context ?? {}) as Record<string, unknown>);
    if (d.decision !== "allow") {
      const n = ++seq;
      let approval = {};
      if (d.decision === "escalate") {
        const id = `apr-${n}`;
        const ep = body.execution_payload_hash;
        approvalRows.set(id, { status: "pending", bound: typeof ep === "string" ? ep.toLowerCase() : "", claimed: false, actor: body.actor_id, action: body.action_type, environment: body.environment });
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
    if (body.actor_id !== p.actor || body.action_type !== p.action || body.environment !== p.environment) {
      return { valid: false, outcome: "deny", verify_error_code: "BINDING_MISMATCH" };
    }
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
      permits.set(token, { bound, consumed: false, actor: row.actor, action: row.action, environment: row.environment });
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

export interface OrderSpec {
  id: number;
  email?: string;
  delivery: "delivered" | "in_transit" | "none" | "cancelled";
  deliveredDaysAgo?: number;
  paid?: string;
  refunded?: string;
  currency?: string;
}

export function makeOrder(spec: OrderSpec): ShopifyOrder {
  const gid = `gid://shopify/Order/${spec.id}`;
  const currency = spec.currency ?? "USD";
  const delivered = spec.delivery === "delivered";
  const deliveredAt = delivered ? new Date(NOW.getTime() - (spec.deliveredDaysAgo ?? 5) * DAY).toISOString() : null;
  const tx = (id: string, kind: string, amount: string) => ({
    id,
    kind,
    status: "SUCCESS",
    gateway: "manual",
    amountSet: { shopMoney: { amount, currencyCode: currency } },
    parentTransaction: null,
  });
  return {
    id: gid,
    name: `#PPS-${spec.id}`,
    email: spec.email ?? "robin@example.com",
    currencyCode: currency,
    cancelledAt: spec.delivery === "cancelled" ? NOW.toISOString() : null,
    fulfillments:
      spec.delivery === "none" || spec.delivery === "cancelled"
        ? []
        : [{ id: `gid://shopify/Fulfillment/${spec.id}`, status: "SUCCESS", displayStatus: delivered ? "DELIVERED" : "IN_TRANSIT", deliveredAt }],
    transactions: [
      tx(`gid://shopify/OrderTransaction/${spec.id}1`, "SALE", spec.paid ?? "34.99"),
      ...(spec.refunded ? [tx(`gid://shopify/OrderTransaction/${spec.id}2`, "REFUND", spec.refunded)] : []),
    ],
  };
}

export class FakeShopify implements ShopifyAdmin {
  orders = new Map<string, ShopifyOrder>();
  refunds: RefundCreateInput[] = [];
  reads = 0;
  failGet = false;
  failRefund = false;
  failRefundRead = false;
  refundStatus = "SUCCESS";
  nativeRefunds = new Map<string, RefundReadback>();
  /** Called with the read count after each getOrder, to simulate a change mid-flight. */
  onRead?: (n: number, fake: FakeShopify) => void;

  constructor(orders: ShopifyOrder[]) {
    for (const o of orders) this.orders.set(o.id, o);
  }

  emailReads = 0;

  async getOrder(orderId: string, options?: GetOrderOptions): Promise<ShopifyOrder | null> {
    if (this.failGet) throw new Error("Shopify Admin API HTTP 503");
    const o = this.orders.get(orderId) ?? null;
    this.reads++;
    const snapshot = o ? (JSON.parse(JSON.stringify(o)) as ShopifyOrder) : null;
    // Like the real query: email is only present when asked for.
    if (snapshot && options?.includeEmail === true) this.emailReads++;
    else if (snapshot) delete snapshot.email;
    this.onRead?.(this.reads, this);
    return snapshot;
  }

  async createRefund(input: RefundCreateInput): Promise<CreatedRefund> {
    if (this.failRefund) throw new Error("refundCreate rejected: boom");
    this.refunds.push(JSON.parse(JSON.stringify(input)));
    const refund = { id: `gid://shopify/Refund/9${this.refunds.length}`, createdAt: NOW.toISOString(), totalRefunded: { amount: input.transactions[0]!.amount, currencyCode: "USD" } };
    this.nativeRefunds.set(refund.id, {
      ...refund, order: { id: input.orderId }, note: input.note,
      transactions: { pageInfo: { hasNextPage: false }, nodes: input.transactions.map((t, i) => ({
        id: `gid://shopify/OrderTransaction/refund-${this.refunds.length}-${i}`,
        kind: t.kind, status: this.refundStatus, gateway: t.gateway,
        amountSet: { shopMoney: { amount: t.amount, currencyCode: "USD" } }, parentTransaction: { id: t.parentId },
      })) },
    });
    return refund;
  }

  async getRefund(refundId: string): Promise<RefundReadback | null> {
    if (this.failRefundRead) throw new Error("native refund read failed");
    const r = this.nativeRefunds.get(refundId);
    return r ? JSON.parse(JSON.stringify(r)) as RefundReadback : null;
  }
}

/** The five demo scenarios, as Shopify orders. */
export function demoOrders(): ShopifyOrder[] {
  return [
    makeOrder({ id: 1001, delivery: "delivered", deliveredDaysAgo: 5, paid: "34.99" }),
    makeOrder({ id: 1002, delivery: "delivered", deliveredDaysAgo: 3, paid: "129.00" }),
    makeOrder({ id: 1003, delivery: "in_transit", paid: "24.50" }),
    makeOrder({ id: 1004, delivery: "delivered", deliveredDaysAgo: 45, paid: "42.00" }),
    makeOrder({ id: 1005, delivery: "delivered", deliveredDaysAgo: 10, paid: "19.99", email: "jo@example.com" }),
  ];
}

