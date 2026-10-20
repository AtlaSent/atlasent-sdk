/**
 * AtlaSent refund-time authorization gate for the Shopify Admin API.
 *
 *   1. read      — fetch the order from Shopify and derive the policy facts
 *   2. evaluate  — finance.payment.authorize, bound to the exact refund
 *   3. verify    — confirm and consume the permit
 *   4. re-read   — the order must still support the refund
 *   5. refund    — refundCreate, ONLY if every step above passed
 *
 * Fail-closed throughout: an unreadable order, an evaluate/verify error, a
 * deny/hold/escalate, a permit that does not verify or was not consumed, a
 * ledger write that fails, or an order that changed after authorization all
 * stop before refundCreate. `guardedShopifyRefund` is the only code in this
 * package that calls refundCreate.
 *
 * WHAT THE PERMIT IS BOUND TO. The guard freezes the refund it will send
 * (order, amount, currency, parent payment, gateway) and hashes it. The
 * digest goes to evaluate as top-level `execution_payload_hash` and is
 * re-presented at verify, so a permit for $18.99 on one order cannot refund
 * a different amount or a different order. The refund Shopify receives is
 * built from that frozen snapshot, never from the caller's input object.
 *
 * WHERE THE FACTS COME FROM. `order_status` and `days_since_delivery` are
 * derived from the order as Shopify reports it (see facts.ts). The caller
 * supplies only an order id and an amount.
 */

import { createHash, randomUUID } from "node:crypto";
import type { AtlaSentClient, EvaluateResponse, VerifyPermitResponse } from "@atlasent/sdk";
import { toOrderGid, type CreatedRefund, type RefundCreateInput, type ShopifyAdmin, type ShopifyOrder } from "./admin.js";
import { centsToMoney, deriveRefundFacts, SUPPORTED_CURRENCY, type RefundFacts } from "./facts.js";
import { refundNote, type PermitLedger } from "./ledger.js";

/** ACT-0024 canonical action: releasing a payment, refund or payout. */
export const FINANCE_PAYMENT_AUTHORIZE = "finance.payment.authorize" as const;

/** Folded into the digest; bump when the digest input changes. */
export const SHOPIFY_REFUND_BINDING_VERSION = "shopify_refund_binding.v1" as const;

export interface RefundRequest {
  /** Numeric id or `gid://shopify/Order/<id>`. */
  orderId: string;
  /** Whole cents, e.g. 1899 for $18.99. */
  amountCents: number;
  /** Free text written into the Shopify refund note after the evaluation id. */
  reason?: string;
}

export interface RefundGuardOptions {
  /** AtlaSent actor, e.g. `shopify-staff:<shop>/<user>` or `agent:pinecone-support`. */
  actor: string;
  /** Must match an environment the org's bundle is published for. */
  environment: string;
  ledger: PermitLedger;
  /** Shop domain, folded into the digest so a permit cannot cross stores. */
  shop: string;
  now?: () => Date;
}

/** The exact refund that will be sent, frozen before evaluate. */
export interface RefundSnapshot {
  shop: string;
  order_id: string;
  amount_cents: number;
  currency: string;
  parent_transaction_id: string;
  gateway: string;
}

export type RefundBlockReason =
  | "deny"
  | "hold"
  | "escalate"
  | "verify_failed"
  | "invalid_request"
  | "order_changed"
  | "error";

export interface RefundDenial {
  refunded: false;
  decision: RefundBlockReason;
  reason: string;
  denyCode?: string;
  /** Random reference for this attempt; also written into the Shopify refund note. */
  gateRef: string;
  auditHash?: string;
  /** Present on escalate when the runtime opened a human-review escalation. */
  escalationId?: string;
  digest?: string;
  facts?: RefundFacts;
}

export interface RefundSuccess {
  refunded: true;
  refund: CreatedRefund;
  amountCents: number;
  gateRef: string;
  auditHash: string;
  digest: string;
  facts: RefundFacts;
  /** Set when the refund ran but the ledger could not record its refund id. */
  ledgerWarning?: string;
}

export type RefundResult = RefundSuccess | RefundDenial;

function sortKeysDeep(val: unknown): unknown {
  if (Array.isArray(val)) return val.map(sortKeysDeep);
  if (val !== null && typeof val === "object") {
    return Object.keys(val as object)
      .sort()
      .reduce<Record<string, unknown>>((acc, k) => {
        acc[k] = sortKeysDeep((val as Record<string, unknown>)[k]);
        return acc;
      }, {});
  }
  return val;
}

/** Bare 64-hex SHA-256 over the canonical snapshot. */
export function computeRefundDigest(snapshot: RefundSnapshot): string {
  return createHash("sha256")
    .update(JSON.stringify(sortKeysDeep({ binding_version: SHOPIFY_REFUND_BINDING_VERSION, ...snapshot })))
    .digest("hex");
}

/** The policy context for one refund. Only Shopify-derived facts. */
export function policyContext(facts: RefundFacts, amountCents: number): Record<string, unknown> {
  return {
    amount_cents: amountCents,
    currency: facts.currency,
    order_status: facts.order_status,
    ...(facts.days_since_delivery !== undefined ? { days_since_delivery: facts.days_since_delivery } : {}),
    refundable_cents: facts.refundable_cents,
    target: { id: facts.order_id },
  };
}

const errorText = (err: unknown) => (err instanceof Error ? err.message : String(err));

function invalid(gateRef: string, reason: string, extra: Partial<RefundDenial> = {}): RefundDenial {
  return { refunded: false, decision: "invalid_request", reason, gateRef, ...extra };
}

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

/** Checks that need no authorization: a refund the order cannot carry is never sent for evaluation. */
function bookkeepingProblem(facts: RefundFacts, amountCents: number): string | undefined {
  if (facts.currency !== SUPPORTED_CURRENCY) return `the demo policy is in ${SUPPORTED_CURRENCY}; this order is in ${facts.currency}`;
  if (facts.parent_transaction === null) return "the order has no successful payment to refund";
  if (amountCents > facts.refundable_cents) {
    return `refund of ${centsToMoney(amountCents)} is more than the ${centsToMoney(facts.refundable_cents)} left to refund`;
  }
  return undefined;
}

async function readFacts(shopify: ShopifyAdmin, orderGid: string, now: Date): Promise<RefundFacts | null> {
  const order: ShopifyOrder | null = await shopify.getOrder(orderGid);
  return order === null ? null : deriveRefundFacts(order, now);
}

export async function guardedShopifyRefund(
  shopify: ShopifyAdmin,
  atlasent: AtlaSentClient,
  request: RefundRequest,
  options: RefundGuardOptions,
): Promise<RefundResult> {
  const now = options.now ?? (() => new Date());
  // Never the permit token: the SDK's evaluationId/permitId IS the token.
  const gateRef = randomUUID();
  const amountCents = request.amountCents;
  if (!Number.isSafeInteger(amountCents) || amountCents <= 0) {
    return invalid(gateRef, "amountCents must be a positive whole number of cents");
  }

  let orderGid: string;
  let facts: RefundFacts | null;
  try {
    orderGid = toOrderGid(request.orderId);
    facts = await readFacts(shopify, orderGid, now());
  } catch (err) {
    return { refunded: false, decision: "error", reason: `could not read the order: ${errorText(err)}`, gateRef };
  }
  if (facts === null) return invalid(gateRef, "order not found");
  const problem = bookkeepingProblem(facts, amountCents);
  if (problem !== undefined) return invalid(gateRef, problem, { facts });
  const parent = facts.parent_transaction as { id: string; gateway: string };

  const snapshot: RefundSnapshot = Object.freeze({
    shop: options.shop,
    order_id: orderGid,
    amount_cents: amountCents,
    currency: facts.currency,
    parent_transaction_id: parent.id,
    gateway: parent.gateway,
  });
  const digest = computeRefundDigest(snapshot);

  let ev: EvaluateResponse;
  try {
    ev = await atlasent.evaluate({
      actor_id: options.actor,
      action_type: FINANCE_PAYMENT_AUTHORIZE,
      environment: options.environment,
      resource_id: orderGid,
      execution_payload_hash: digest,
      context: policyContext(facts, amountCents),
    });
  } catch (err) {
    return { refunded: false, decision: "error", reason: `evaluate failed: ${errorText(err)}`, gateRef, digest, facts };
  }

  if (ev.decision !== "allow") {
    const decision: RefundBlockReason = ev.decision === "hold" || ev.decision === "escalate" ? ev.decision : "deny";
    return {
      refunded: false,
      decision,
      reason: ev.reason || `blocked by decision=${ev.decision}`,
      ...(ev.deny_code !== null ? { denyCode: ev.deny_code } : {}),
      gateRef,
      ...(ev.auditHash ? { auditHash: ev.auditHash } : {}),
      ...(ev.escalationId !== undefined ? { escalationId: ev.escalationId } : {}),
      digest,
      facts,
    };
  }
  const evidence = { gateRef, ...(ev.auditHash ? { auditHash: ev.auditHash } : {}), digest, facts };

  let verified: VerifyPermitResponse;
  try {
    verified = await atlasent.verifyPermit({
      permitId: ev.permitId,
      agent: options.actor,
      action: FINANCE_PAYMENT_AUTHORIZE,
      environment: options.environment,
      execution_hash: digest,
    });
  } catch (err) {
    return { refunded: false, decision: "error", reason: `verifyPermit failed: ${errorText(err)}`, ...evidence };
  }
  if (verified.verified !== true) {
    return { refunded: false, decision: "verify_failed", reason: `permit did not verify: outcome=${verified.outcome}`, ...evidence };
  }
  if (verified.consumed !== true) {
    // A permit that verified without being burned could be presented again.
    return { refunded: false, decision: "verify_failed", reason: "permit verified but was not reported consumed", ...evidence };
  }

  // Recorded before the refund, so the webhook can always account for it.
  try {
    await options.ledger.recordAuthorized({
      gate_ref: gateRef,
      permit_sha256: sha256(ev.permitId),
      audit_hash: ev.auditHash,
      order_id: orderGid,
      amount_cents: amountCents,
      actor_id: options.actor,
      authorized_at: now().toISOString(),
    });
  } catch (err) {
    return { refunded: false, decision: "error", reason: `could not record the permit: ${errorText(err)}`, ...evidence };
  }

  // Time passed during evaluate/verify; the order must still carry this refund.
  let current: RefundFacts | null;
  try {
    current = await readFacts(shopify, orderGid, now());
  } catch (err) {
    return { refunded: false, decision: "error", reason: `could not re-read the order: ${errorText(err)}`, ...evidence };
  }
  if (
    current === null ||
    current.order_status !== facts.order_status ||
    current.parent_transaction?.id !== parent.id ||
    current.currency !== facts.currency ||
    current.refundable_cents < amountCents
  ) {
    return { refunded: false, decision: "order_changed", reason: "the order changed after the refund was authorized", ...evidence };
  }

  const input: RefundCreateInput = {
    orderId: snapshot.order_id,
    note: refundNote(gateRef, request.reason),
    notify: false,
    transactions: [
      {
        orderId: snapshot.order_id,
        parentId: snapshot.parent_transaction_id,
        kind: "REFUND",
        gateway: snapshot.gateway,
        amount: centsToMoney(snapshot.amount_cents),
      },
    ],
  };

  // ONLY reachable after allow + verified + consumed + recorded + re-read.
  let refund: CreatedRefund;
  try {
    refund = await shopify.createRefund(input);
  } catch (err) {
    return { refunded: false, decision: "error", reason: `refundCreate failed: ${errorText(err)}`, ...evidence };
  }

  let ledgerWarning: string | undefined;
  try {
    await options.ledger.recordExecuted(gateRef, refund.id);
  } catch (err) {
    ledgerWarning = `refund ${refund.id} ran but the ledger did not record it: ${errorText(err)}`;
  }

  return {
    refunded: true,
    refund,
    amountCents,
    gateRef,
    auditHash: ev.auditHash,
    digest,
    facts,
    ...(ledgerWarning !== undefined ? { ledgerWarning } : {}),
  };
}

/** Read-only: where a manager review stands. Does not issue the refund. */
export async function managerApprovalStatus(
  atlasent: AtlaSentClient,
  escalationId: string,
): Promise<{ status: string; resolvedBy: string | null; resolvedAt: string | null }> {
  const { escalation } = await atlasent.getHitlEscalation(escalationId);
  return { status: escalation.status, resolvedBy: escalation.resolved_by, resolvedAt: escalation.resolved_at };
}
