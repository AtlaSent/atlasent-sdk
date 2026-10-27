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
 * stop before refundCreate. After a send, errors remain unconfirmed until
 * exact native transaction readback; another send is interlocked.
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
import { normalizeShopDomain, toOrderGid, type CreatedRefund, type RefundCreateInput, type ShopifyAdmin, type ShopifyOrder } from "./admin.js";
import { centsToMoney, collectSupportedRefundFacts, SUPPORTED_CURRENCY, type RefundFacts } from "./facts.js";
import { refundNote, RefundReservationError, type PendingApproval, type PermitLedger } from "./ledger.js";
import { confirmRefundReadback } from "./refund-completion.js";
import { CLAIMABLE_APPROVAL_STATUSES, type ApprovalsApi } from "./approvals.js";
import { outcomeOf, REFUND_DECISION_SCHEMA, type RefundDecisionRecord } from "./decision-record.js";

/** ACT-0024 canonical action: releasing a payment, refund or payout. */
export const FINANCE_PAYMENT_AUTHORIZE = "finance.payment.authorize" as const;

/** Folded into the digest; bump when the digest input changes. */
export const SHOPIFY_REFUND_BINDING_VERSION = "shopify_refund_binding.v1" as const;

export interface RefundRequest {
  /** Stable upstream case/request ID, reused on delivery retries; never an authority claim. */
  businessRequestId?: string;
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
  /** Called once per decision, refunded or not, e.g. to append to the evidence log. Its failure never changes the result. */
  onDecision?: (record: RefundDecisionRecord) => void | Promise<void>;
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
  | "unconfirmed"
  | "duplicate_request"
  | "reconciliation_required"
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
  /** Present on escalate/hold when the runtime created an approval request; resume with {@link resumeApprovedShopifyRefund}. */
  approvalRequestId?: string;
  /** Set when the approval request could not be saved for resuming. */
  approvalWarning?: string;
  digest?: string;
  facts?: RefundFacts;
  /** Set when `onDecision` failed. */
  logWarning?: string;
  /** Provider acknowledgement only; does not establish a successful refund. */
  refundId?: string;
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
  /** Set when `onDecision` failed. */
  logWarning?: string;
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

/** The order still carries this exact refund: same status, parent payment, currency, and enough left to refund. */
function sourceFactsHash(facts: RefundFacts): string {
  return sha256(JSON.stringify(sortKeysDeep(facts)));
}

function stillSupports(current: RefundFacts | null, facts: RefundFacts, amountCents: number): boolean {
  return (
    current !== null &&
    sourceFactsHash(current) === sourceFactsHash(facts) &&
    current.refundable_cents >= amountCents
  );
}

async function readFacts(shopify: ShopifyAdmin, orderGid: string, now: Date): Promise<RefundFacts | null> {
  const order: ShopifyOrder | null = await shopify.getOrder(orderGid);
  return order === null ? null : collectSupportedRefundFacts(order, orderGid, now);
}

/** A send or readback failure stays unresolved and keeps the payment interlock. */
async function executeAuthorizedRefund(
  shopify: ShopifyAdmin, input: RefundCreateInput,
  evidence: Omit<RefundSuccess, "refunded" | "refund">, options: RefundGuardOptions,
): Promise<RefundResult> {
  let refund: CreatedRefund | undefined;
  const unresolved = async (detail: string): Promise<RefundDenial> => {
    let reason = `${detail}; reconcile the original request before retrying`;
    try {
      await options.ledger.recordUnconfirmed(evidence.gateRef, detail, refund?.id);
    } catch (err) {
      // The pre-send entry remains unresolved even if this update fails.
      reason += `; could not record the uncertain outcome: ${errorText(err)}`;
    }
    return { refunded: false, decision: "unconfirmed", reason, ...evidence, ...(refund ? { refundId: refund.id } : {}) };
  };
  try {
    refund = await shopify.createRefund(input);
  } catch (err) {
    return unresolved(`refundCreate outcome is unknown: ${errorText(err)}`);
  }
  try {
    const native = await shopify.getRefund?.(refund.id);
    if (!confirmRefundReadback(native, refund.id, input, evidence.facts.currency)) {
      return unresolved("Shopify has not confirmed the exact successful refund transaction");
    }
  } catch (err) {
    return unresolved(`refund readback failed: ${errorText(err)}`);
  }
  let ledgerWarning: string | undefined;
  try {
    await options.ledger.recordExecuted(evidence.gateRef, refund.id);
  } catch (err) {
    ledgerWarning = `refund ${refund.id} was confirmed but the ledger did not record it: ${errorText(err)}`;
  }
  return { refunded: true, refund, ...evidence, ...(ledgerWarning ? { ledgerWarning } : {}) };
}

export async function guardedShopifyRefund(
  shopify: ShopifyAdmin,
  atlasent: AtlaSentClient,
  request: RefundRequest,
  options: RefundGuardOptions,
): Promise<RefundResult> {
  const frozen = { ...request };
  let bound: RefundGuardOptions;
  try { bound = { ...options, shop: normalizeShopDomain(options.shop) }; }
  catch { return invalid(randomUUID(), "invalid configured shop domain"); }
  const result = await decideShopifyRefund(shopify, atlasent, frozen, bound);
  return emitDecision(result, frozen.orderId, frozen.amountCents, bound, null);
}

/** Calls `onDecision` with the record for one result; a failing callback sets `logWarning` and never changes the outcome. */
async function emitDecision<T extends RefundResult>(
  result: T,
  requestedOrderId: string,
  requestedAmountCents: number,
  options: RefundGuardOptions,
  approval: { id: string; decision: string; reason: string; orderRef: string | null; currency: string | null } | null,
): Promise<T> {
  if (options.onDecision === undefined) return result;
  const facts = result.facts;
  const approvalRequestId = approval?.id ?? (result.refunded ? undefined : result.approvalRequestId);
  const record: RefundDecisionRecord = {
    schema: REFUND_DECISION_SCHEMA,
    at: (options.now ?? (() => new Date()))().toISOString(),
    system: "shopify",
    gate_ref: result.gateRef,
    actor: options.actor,
    environment: options.environment,
    target: facts?.order_id ?? requestedOrderId,
    order_ref: facts?.order_name ?? approval?.orderRef ?? null,
    amount_cents: Number.isSafeInteger(requestedAmountCents) ? requestedAmountCents : null,
    currency: facts?.currency ?? approval?.currency ?? null,
    outcome: outcomeOf(result.refunded, result.refunded ? "allow" : result.decision),
    decision: approval?.decision ?? (result.refunded ? "allow" : result.decision),
    deny_code: result.refunded ? null : (result.denyCode ?? null),
    reason: approval?.reason ?? (result.refunded ? "within policy" : result.reason),
    audit_hash: result.auditHash || null,
    refund_id: result.refunded ? result.refund.id : (result.refundId ?? null),
    order_status: facts?.order_status ?? null,
    days_since_delivery: facts?.days_since_delivery ?? null,
    approval_request_id: approvalRequestId ?? null,
  };
  try {
    await options.onDecision(record);
    return result;
  } catch (err) {
    return { ...result, logWarning: `the decision was not logged: ${errorText(err)}` };
  }
}

async function decideShopifyRefund(
  shopify: ShopifyAdmin,
  atlasent: AtlaSentClient,
  request: RefundRequest,
  options: RefundGuardOptions,
): Promise<RefundResult> {
  const now = options.now ?? (() => new Date());
  // Never the permit token: the SDK's evaluationId/permitId IS the token.
  const gateRef = randomUUID();
  const amountCents = request.amountCents;
  if (request.businessRequestId !== undefined && !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(request.businessRequestId)) {
    return invalid(gateRef, "businessRequestId must be a stable 1–128 character request identifier");
  }
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
      context: { ...policyContext(facts, amountCents), environment: options.environment },
    });
  } catch (err) {
    return { refunded: false, decision: "error", reason: `evaluate failed: ${errorText(err)}`, gateRef, digest, facts };
  }

  if (ev.decision !== "allow") {
    const decision: RefundBlockReason = ev.decision === "hold" || ev.decision === "escalate" ? ev.decision : "deny";
    let approvalWarning: string | undefined;
    const approvalRequestId = (decision === "hold" || decision === "escalate") ? ev.approvalRequestId : undefined;
    if (approvalRequestId !== undefined) {
      // Freeze the refund under its approval, so resuming can only issue this one.
      try {
        await options.ledger.recordPendingApproval({
          approval_request_id: approvalRequestId,
          gate_ref: gateRef,
          actor_id: options.actor,
          environment: options.environment,
          order_id: orderGid,
          order_ref: facts.order_name,
          amount_cents: amountCents,
          snapshot: { ...snapshot },
          digest,
          source_facts_hash: sourceFactsHash(facts),
          ...(request.businessRequestId ? { business_request_id: request.businessRequestId } : {}),
          ...(request.reason ? { reason: request.reason } : {}),
          created_at: now().toISOString(),
        });
      } catch (err) {
        approvalWarning = `the approval request could not be saved, so it cannot be resumed here: ${errorText(err)}`;
      }
    }
    return {
      refunded: false,
      decision,
      reason: ev.reason || `blocked by decision=${ev.decision}`,
      ...(ev.deny_code !== null ? { denyCode: ev.deny_code } : {}),
      gateRef,
      ...(ev.auditHash ? { auditHash: ev.auditHash } : {}),
      ...(ev.escalationId !== undefined ? { escalationId: ev.escalationId } : {}),
      ...(approvalRequestId !== undefined ? { approvalRequestId } : {}),
      ...(approvalWarning !== undefined ? { approvalWarning } : {}),
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
      shop: snapshot.shop,
      environment: options.environment,
      parent_transaction_id: snapshot.parent_transaction_id,
      currency: snapshot.currency,
      gateway: snapshot.gateway,
      execution_digest: digest,
      refund_note: refundNote(gateRef, request.reason),
      ...(request.businessRequestId ? { business_request_id: request.businessRequestId } : {}),
    });
  } catch (err) {
    if (err instanceof RefundReservationError) {
      // Recovery needs the existing execution reference, not this retry's
      // unrecorded UUID or its newly evaluated audit/payload binding.
      return { refunded: false, decision: err.code === "request_conflict" ? "invalid_request" : err.code, reason: err.message, gateRef: err.gateRef, facts };
    }
    return { refunded: false, decision: "error", reason: `could not record the permit: ${errorText(err)}`, ...evidence };
  }

  // From here on, every stop must cancel the ledger entry, or its gateRef
  // (returned to the caller) could vouch for a refund made around the gate.
  const abort = async (decision: RefundBlockReason, reason: string): Promise<RefundDenial> => {
    try {
      await options.ledger.recordAborted(gateRef, decision);
    } catch (err) {
      reason += `; the ledger entry could not be cancelled: ${errorText(err)}`;
    }
    return { refunded: false, decision, reason, ...evidence };
  };

  // Time passed during evaluate/verify; the order must still carry this refund.
  let current: RefundFacts | null;
  try {
    current = await readFacts(shopify, orderGid, now());
  } catch (err) {
    return abort("error", `could not re-read the order: ${errorText(err)}`);
  }
  if (!stillSupports(current, facts, amountCents)) {
    return abort("order_changed", "the order changed after the refund was authorized");
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
  return executeAuthorizedRefund(shopify, input, { ...evidence, amountCents, auditHash: ev.auditHash }, options);
}

/** Read-only: where a manager review stands. Does not issue the refund. */
export async function managerApprovalStatus(
  atlasent: AtlaSentClient,
  escalationId: string,
): Promise<{ status: string; resolvedBy: string | null; resolvedAt: string | null }> {
  const { escalation } = await atlasent.getHitlEscalation(escalationId);
  return { status: escalation.status, resolvedBy: escalation.resolved_by, resolvedAt: escalation.resolved_at };
}

export interface ResumeRequest {
  approvalRequestId: string;
  /** Who asked to resume (e.g. the staff member who clicked "Check approval"). Recorded, never authorizes. */
  resumedBy?: string;
}

/**
 * Resume an escalated refund after a person decided it in the AtlaSent console.
 *
 * Single-shot (call it again later while the approval is pending):
 *   - pending → `hold`, nothing changes;
 *   - declined, expired, revoked, ... → `deny` (`APPROVAL_<STATUS>`), closed;
 *   - approved → re-read the order (it must still carry the frozen refund),
 *     claim the ONE permit, check it is bound to this refund's digest, verify
 *     (consumed), record it, re-read again, then refundCreate.
 *
 * Only a refund this gate escalated and froze can be resumed, and only
 * exactly as it was evaluated. Pre-send stops cancel the ledger entry;
 * uncertain sends retain the entry and require native reconciliation.
 */
export async function resumeApprovedShopifyRefund(
  shopify: ShopifyAdmin,
  atlasent: AtlaSentClient,
  approvals: ApprovalsApi,
  request: ResumeRequest,
  options: RefundGuardOptions,
): Promise<RefundResult> {
  try { options = { ...options, shop: normalizeShopDomain(options.shop) }; }
  catch { return invalid("", "invalid configured shop domain"); }
  const now = options.now ?? (() => new Date());
  const id = request.approvalRequestId;
  let pending: PendingApproval | undefined;
  try {
    pending = await options.ledger.getPendingApproval(id);
  } catch (err) {
    return { refunded: false, decision: "error", reason: `could not read the pending approval: ${errorText(err)}`, gateRef: "" };
  }
  if (pending === undefined) {
    return { refunded: false, decision: "invalid_request", reason: "this gate did not escalate that approval request, so it cannot resume it", gateRef: "" };
  }
  const p = pending;
  const gateRef = p.gate_ref;
  if (p.resolved !== undefined) {
    return { refunded: false, decision: "invalid_request", reason: `this approval was already resolved (${p.resolved.outcome})`, gateRef, approvalRequestId: id };
  }
  if ((p.snapshot as { shop?: unknown }).shop !== options.shop) {
    return { refunded: false, decision: "invalid_request", reason: "that approval request belongs to a different shop", gateRef: "" };
  }
  if (p.environment !== options.environment) {
    return { refunded: false, decision: "invalid_request", reason: "that approval request belongs to a different environment", gateRef: "" };
  }
  const resumedBy = request.resumedBy ? ` (resumed by ${request.resumedBy})` : "";
  const finish = async (result: RefundResult, decision: string, reason: string) =>
    emitDecision(result, p.order_id, p.amount_cents, options, {
      id,
      decision,
      reason: reason + resumedBy,
      orderRef: p.order_ref ?? null,
      currency: typeof p.snapshot.currency === "string" ? p.snapshot.currency : null,
    });
  const close = async (outcome: NonNullable<PendingApproval["resolved"]>["outcome"], detail: string) => {
    try {
      await options.ledger.resolvePendingApproval(id, { outcome, at: now().toISOString(), detail });
    } catch {
      // The decision itself stands; a stale pending row can only be resumed into the same checks again.
    }
  };

  let status;
  try {
    status = await approvals.getStatus(id);
  } catch (err) {
    return { refunded: false, decision: "error", reason: `could not read the approval: ${errorText(err)}`, gateRef, approvalRequestId: id };
  }
  if (!status.found) {
    await close("stopped", "approval request not found");
    return finish({ refunded: false, decision: "error", reason: "the runtime has no such approval request", gateRef, approvalRequestId: id }, "approval_not_found", "approval request not found");
  }
  if (status.status === "pending") {
    return { refunded: false, decision: "hold", reason: "still waiting for a manager's decision", gateRef, approvalRequestId: id };
  }
  if (!CLAIMABLE_APPROVAL_STATUSES.has(status.status)) {
    const code = `APPROVAL_${status.status.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}`;
    await close("not_approved", status.status);
    return finish(
      { refunded: false, decision: "deny", denyCode: code, reason: `the approval was ${status.status.replace(/_/g, " ")}; nothing was refunded`, gateRef, approvalRequestId: id },
      "approval_not_granted",
      `approval ${status.status}`,
    );
  }

  // Approved. Before claiming the one permit, the order must still carry exactly the frozen refund.
  const snap = p.snapshot as unknown as RefundSnapshot;
  const stop = async (decision: RefundBlockReason, reason: string, facts?: RefundFacts | null) => {
    await close("stopped", reason);
    return finish({ refunded: false, decision, reason, gateRef, approvalRequestId: id, digest: p.digest, ...(facts ? { facts } : {}) }, "approval_stopped", reason);
  };
  let facts: RefundFacts | null;
  try {
    facts = await readFacts(shopify, p.order_id, now());
  } catch (err) {
    return { refunded: false, decision: "error", reason: `could not read the order: ${errorText(err)}`, gateRef, approvalRequestId: id };
  }
  const same =
    facts !== null &&
    facts.parent_transaction !== null &&
    computeRefundDigest({
      shop: snap.shop,
      order_id: facts.order_id,
      amount_cents: p.amount_cents,
      currency: facts.currency,
      parent_transaction_id: facts.parent_transaction.id,
      gateway: facts.parent_transaction.gateway,
    }) === p.digest;
  if (!same || facts === null || facts.refundable_cents < p.amount_cents ||
      p.source_facts_hash === undefined || sourceFactsHash(facts) !== p.source_facts_hash) {
    return stop("order_changed", "the order changed after the refund was escalated; the approval does not cover it", facts);
  }

  const claim = await approvals.claimPermit(id).catch((err: unknown) => ({ claimed: false as const, failure: errorText(err) }));
  if (!claim.claimed) return stop("verify_failed", `the approved permit could not be claimed: ${claim.failure}`, facts);
  if (claim.executionHashExpected !== undefined && claim.executionHashExpected.toLowerCase() !== p.digest) {
    return stop("verify_failed", "the approved permit is bound to a different refund", facts);
  }

  let verified: VerifyPermitResponse;
  try {
    verified = await atlasent.verifyPermit({
      permitId: claim.permitToken,
      agent: p.actor_id,
      action: FINANCE_PAYMENT_AUTHORIZE,
      environment: p.environment,
      execution_hash: p.digest,
    });
  } catch (err) {
    return stop("error", `verifyPermit failed: ${errorText(err)}`, facts);
  }
  if (verified.verified !== true || verified.consumed !== true) {
    return stop("verify_failed", verified.verified !== true ? `permit did not verify: outcome=${verified.outcome}` : "permit verified but was not reported consumed", facts);
  }

  try {
    await options.ledger.recordAuthorized({
      gate_ref: gateRef,
      permit_sha256: createHash("sha256").update(claim.permitToken).digest("hex"),
      audit_hash: "",
      order_id: p.order_id,
      amount_cents: p.amount_cents,
      actor_id: p.actor_id,
      authorized_at: now().toISOString(),
      shop: snap.shop,
      environment: p.environment,
      parent_transaction_id: snap.parent_transaction_id,
      currency: snap.currency,
      gateway: snap.gateway,
      execution_digest: p.digest,
      refund_note: refundNote(gateRef, `${p.reason ? `${p.reason}; ` : ""}approved by a manager`),
      approval_request_id: id,
      ...(p.business_request_id ? { business_request_id: p.business_request_id } : {}),
    });
  } catch (err) {
    if (err instanceof RefundReservationError) {
      await close("stopped", err.message);
      return finish({ refunded: false, decision: err.code === "request_conflict" ? "invalid_request" : err.code, reason: err.message, gateRef: err.gateRef }, "approval_stopped", err.message);
    }
    return stop("error", `could not record the permit: ${errorText(err)}`, facts);
  }
  const abort = async (decision: RefundBlockReason, reason: string) => {
    try {
      await options.ledger.recordAborted(gateRef, decision);
    } catch (err) {
      reason += `; the ledger entry could not be cancelled: ${errorText(err)}`;
    }
    return stop(decision, reason, facts);
  };

  let current: RefundFacts | null;
  try {
    current = await readFacts(shopify, p.order_id, now());
  } catch (err) {
    return abort("error", `could not re-read the order: ${errorText(err)}`);
  }
  if (!stillSupports(current, facts, p.amount_cents)) {
    return abort("order_changed", "the order changed after the refund was approved");
  }

  const result = await executeAuthorizedRefund(shopify, {
      orderId: p.order_id,
      note: refundNote(gateRef, `${p.reason ? `${p.reason}; ` : ""}approved by a manager`),
      notify: false,
      transactions: [
        { orderId: p.order_id, parentId: snap.parent_transaction_id, kind: "REFUND", gateway: snap.gateway, amount: centsToMoney(p.amount_cents) },
      ],
    }, { gateRef, amountCents: p.amount_cents, auditHash: "", digest: p.digest, facts }, options);
  if (result.refunded) await close("refunded", result.refund.id);
  else await close("stopped", result.reason);
  return finish(
    result,
    result.refunded ? "allow_after_approval" : "unconfirmed",
    result.refunded ? "approved by a manager" : result.reason,
  );
}

