/**
 * AtlaSent refund-time authorization gate for Stripe.
 *
 *   1. read      — the PaymentIntent from Stripe, delivery from the store
 *   2. evaluate  — finance.payment.authorize, bound to the exact refund
 *   3. verify    — confirm and consume the permit
 *   4. re-read   — the payment and order must still support the refund
 *   5. refund    — POST /v1/refunds, ONLY if every step above passed
 *
 * Fail-closed throughout: an unreadable payment or order, an evaluate/verify
 * error, a deny/hold/escalate, a permit that does not verify or was not
 * consumed, a ledger write that fails, or a payment that changed after
 * authorization all stop before POST /v1/refunds. Any stop after the permit
 * is recorded cancels the ledger entry, so its gateRef can never vouch for a
 * refund made elsewhere. `guardedStripeRefund` is the only code in this
 * package that creates a refund.
 *
 * WHAT THE PERMIT IS BOUND TO. The refund is frozen (account, PaymentIntent,
 * charge, order reference, amount, currency) and hashed; the digest is sent
 * as `execution_payload_hash` and re-presented at verify. The refund Stripe
 * receives is built from that snapshot, and carries the gateRef both in its
 * metadata and as its Idempotency-Key, so a retried call cannot refund twice.
 */

import { createHash, randomUUID } from "node:crypto";
import type { AtlaSentClient, EvaluateResponse, VerifyPermitResponse } from "@atlasent/sdk";
import { assertPaymentIntentId, type StripeApi, type StripeRefund } from "./stripe.js";
import { centsToMoney, deriveStripeRefundFacts, SUPPORTED_CURRENCY, type DeliveryFactsSource, type StripeRefundFacts } from "./facts.js";
import type { PendingApproval, PermitLedger } from "./ledger.js";
import { CLAIMABLE_APPROVAL_STATUSES, type ApprovalsApi } from "./approvals.js";
import { outcomeOf, REFUND_DECISION_SCHEMA, type RefundDecisionRecord } from "./decision-record.js";

/** ACT-0024 canonical action: releasing a payment, refund or payout. */
export const FINANCE_PAYMENT_AUTHORIZE = "finance.payment.authorize" as const;

/** Folded into the digest; bump when the digest input changes. */
export const STRIPE_REFUND_BINDING_VERSION = "stripe_refund_binding.v1" as const;

/** Stripe refund statuses that mean the refund was accepted. */
const ACCEPTED_REFUND_STATUSES = new Set(["succeeded", "pending", "requires_action"]);

export interface StripeRefundRequest {
  paymentIntentId: string;
  /** Whole cents, e.g. 1899 for $18.99. */
  amountCents: number;
  /** Free text recorded in the refund metadata. */
  reason?: string;
}

export interface StripeRefundGuardOptions {
  /** AtlaSent actor, e.g. `support-tool:<user>` or `agent:pinecone-support`. */
  actor: string;
  /** Must match an environment the org's bundle is published for. */
  environment: string;
  ledger: PermitLedger;
  /** The store's order system, for delivery facts. */
  delivery: DeliveryFactsSource;
  /** Label for the Stripe account (e.g. its `acct_` id), folded into the digest. */
  account: string;
  /** PaymentIntent metadata key holding the order reference. Default `order_id`. */
  orderRefKey?: string;
  now?: () => Date;
  /** Called once per decision, refunded or not, e.g. to append to the evidence log. Its failure never changes the result. */
  onDecision?: (record: RefundDecisionRecord) => void | Promise<void>;
}

export interface StripeRefundSnapshot {
  account: string;
  payment_intent: string;
  charge: string;
  order_ref: string;
  amount_cents: number;
  currency: string;
}

export type StripeRefundBlockReason =
  | "deny"
  | "hold"
  | "escalate"
  | "verify_failed"
  | "invalid_request"
  | "payment_changed"
  | "error";

export interface StripeRefundDenial {
  refunded: false;
  decision: StripeRefundBlockReason;
  reason: string;
  denyCode?: string;
  gateRef: string;
  auditHash?: string;
  escalationId?: string;
  /** Present on escalate/hold when the runtime created an approval request; resume with {@link resumeApprovedStripeRefund}. */
  approvalRequestId?: string;
  /** Set when the approval request could not be saved for resuming. */
  approvalWarning?: string;
  digest?: string;
  facts?: StripeRefundFacts;
  logWarning?: string;
}

export interface StripeRefundSuccess {
  /** Legacy flag means accepted by Stripe, not necessarily completed. Read completion. */
  refunded: true;
  completion: "succeeded" | "pending" | "requires_action";
  refund: StripeRefund;
  amountCents: number;
  gateRef: string;
  auditHash: string;
  digest: string;
  facts: StripeRefundFacts;
  ledgerWarning?: string;
  logWarning?: string;
}

export type StripeRefundResult = StripeRefundSuccess | StripeRefundDenial;

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

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

export function computeStripeRefundDigest(snapshot: StripeRefundSnapshot): string {
  return sha256(JSON.stringify(sortKeysDeep({ binding_version: STRIPE_REFUND_BINDING_VERSION, ...snapshot })));
}

/** The policy context: only Stripe- and order-system-derived facts. */
export function policyContext(facts: StripeRefundFacts, amountCents: number): Record<string, unknown> {
  return {
    amount_cents: amountCents,
    currency: facts.currency,
    order_status: facts.order_status,
    ...(facts.days_since_delivery !== undefined ? { days_since_delivery: facts.days_since_delivery } : {}),
    refundable_cents: facts.refundable_cents,
    target: { id: facts.payment_intent },
  };
}

const errorText = (err: unknown) => (err instanceof Error ? err.message : String(err));

function bookkeepingProblem(f: StripeRefundFacts, amountCents: number): string | undefined {
  if (!f.payment_succeeded || f.charge === null) return "the payment has not succeeded, so there is nothing to refund";
  if (f.disputed) return "the charge is disputed; resolve the dispute instead of refunding";
  if (f.order_ref === null) return "the payment is not linked to an order, so delivery cannot be checked";
  if (f.currency !== SUPPORTED_CURRENCY) return `the demo policy is in ${SUPPORTED_CURRENCY}; this payment is in ${f.currency}`;
  if (amountCents > f.refundable_cents) {
    return `refund of ${centsToMoney(amountCents)} is more than the ${centsToMoney(f.refundable_cents)} left to refund`;
  }
  return undefined;
}

/** The payment and order still carry this exact refund: same charge and order, not disputed, same delivery status, enough left. */
function stillSupports(current: StripeRefundFacts | null, snapshot: StripeRefundSnapshot, orderStatus: string): boolean {
  return (
    current !== null &&
    current.payment_intent === snapshot.payment_intent &&
    current.currency === snapshot.currency &&
    current.payment_succeeded &&
    !current.disputed &&
    current.charge === snapshot.charge &&
    current.order_ref === snapshot.order_ref &&
    current.order_status === orderStatus &&
    current.refundable_cents >= snapshot.amount_cents
  );
}

async function readFacts(
  stripe: StripeApi,
  piId: string,
  options: StripeRefundGuardOptions,
  now: Date,
): Promise<StripeRefundFacts | null> {
  const pi = await stripe.getPaymentIntent(piId);
  if (pi === null) return null;
  if (pi.id !== piId) throw new Error("provider returned a different payment");
  const refunds = await stripe.listRefunds(piId);
  let completedRefundCents = 0;
  for (const refund of refunds) {
    if (refund.payment_intent !== piId || refund.charge !== pi.latest_charge?.id ||
        typeof refund.currency !== "string" || refund.currency.toUpperCase() !== pi.currency.toUpperCase() ||
        !Number.isSafeInteger(refund.amount) || refund.amount <= 0) {
      throw new Error("refund history does not match the payment");
    }
    if (!["succeeded", "failed", "canceled"].includes(refund.status)) {
      throw new Error("an existing refund is pending, requires action, or has an unknown status; reconcile it before another refund");
    }
    if (refund.status === "succeeded") completedRefundCents += refund.amount;
    if (!Number.isSafeInteger(completedRefundCents)) throw new Error("refund history amount is out of range");
  }
  if (completedRefundCents > (pi.latest_charge?.amount_refunded ?? 0)) {
    throw new Error("refund history and charge balance disagree; reconcile before another refund");
  }
  const raw = pi.metadata?.[options.orderRefKey ?? "order_id"];
  const orderRef = typeof raw === "string" && raw.trim().length > 0 ? raw.trim() : null;
  const delivery = orderRef === null ? null : await options.delivery.getDeliveryFacts(orderRef);
  return deriveStripeRefundFacts(pi, delivery, orderRef, now);
}

export async function guardedStripeRefund(
  stripe: StripeApi,
  atlasent: AtlaSentClient,
  request: StripeRefundRequest,
  options: StripeRefundGuardOptions,
): Promise<StripeRefundResult> {
  const result = await decideStripeRefund(stripe, atlasent, request, options);
  return emitDecision(result, request.paymentIntentId, request.amountCents, options, null);
}

/** Calls `onDecision` with the record for one result; a failing callback sets `logWarning` and never changes the outcome. */
async function emitDecision<T extends StripeRefundResult>(
  result: T,
  requestedPaymentIntentId: string,
  requestedAmountCents: number,
  options: StripeRefundGuardOptions,
  approval: { id: string; decision: string; reason: string; orderRef: string | null; currency: string | null } | null,
): Promise<T> {
  if (options.onDecision === undefined) return result;
  const facts = result.facts;
  const approvalRequestId = approval?.id ?? (result.refunded ? undefined : result.approvalRequestId);
  const record: RefundDecisionRecord = {
    schema: REFUND_DECISION_SCHEMA,
    at: (options.now ?? (() => new Date()))().toISOString(),
    system: "stripe",
    gate_ref: result.gateRef,
    actor: options.actor,
    environment: options.environment,
    target: facts?.payment_intent ?? requestedPaymentIntentId,
    order_ref: facts?.order_ref ?? approval?.orderRef ?? null,
    amount_cents: Number.isSafeInteger(requestedAmountCents) ? requestedAmountCents : null,
    currency: facts?.currency ?? approval?.currency ?? null,
    outcome: outcomeOf(result.refunded, result.refunded ? "allow" : result.decision),
    decision: approval?.decision ?? (result.refunded ? "allow" : result.decision),
    deny_code: result.refunded ? null : (result.denyCode ?? null),
    reason: approval?.reason ?? (result.refunded ? "within policy" : result.reason),
    audit_hash: result.auditHash || null,
    refund_id: result.refunded ? result.refund.id : null,
    processor_status: result.refunded ? result.refund.status : null,
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

async function decideStripeRefund(
  stripe: StripeApi,
  atlasent: AtlaSentClient,
  request: StripeRefundRequest,
  options: StripeRefundGuardOptions,
): Promise<StripeRefundResult> {
  const now = options.now ?? (() => new Date());
  // Never the permit token: the SDK's evaluationId/permitId IS the token.
  const gateRef = randomUUID();
  const amountCents = request.amountCents;
  const invalid = (reason: string, extra: Partial<StripeRefundDenial> = {}): StripeRefundDenial => ({
    refunded: false,
    decision: "invalid_request",
    reason,
    gateRef,
    ...extra,
  });
  if (!Number.isSafeInteger(amountCents) || amountCents <= 0) return invalid("amountCents must be a positive whole number of cents");

  let piId: string;
  let facts: StripeRefundFacts | null;
  try {
    piId = assertPaymentIntentId(request.paymentIntentId);
    facts = await readFacts(stripe, piId, options, now());
  } catch (err) {
    return { refunded: false, decision: "error", reason: `could not read the payment or order: ${errorText(err)}`, gateRef };
  }
  if (facts === null) return invalid("payment not found");
  const problem = bookkeepingProblem(facts, amountCents);
  if (problem !== undefined) return invalid(problem, { facts });

  const snapshot: StripeRefundSnapshot = Object.freeze({
    account: options.account,
    payment_intent: piId,
    charge: facts.charge as string,
    order_ref: facts.order_ref as string,
    amount_cents: amountCents,
    currency: facts.currency,
  });
  const digest = computeStripeRefundDigest(snapshot);

  let ev: EvaluateResponse;
  try {
    ev = await atlasent.evaluate({
      actor_id: options.actor,
      action_type: FINANCE_PAYMENT_AUTHORIZE,
      environment: options.environment,
      resource_id: piId,
      execution_payload_hash: digest,
      context: policyContext(facts, amountCents),
    });
  } catch (err) {
    return { refunded: false, decision: "error", reason: `evaluate failed: ${errorText(err)}`, gateRef, digest, facts };
  }

  if (ev.decision !== "allow") {
    const decision: StripeRefundBlockReason = ev.decision === "hold" || ev.decision === "escalate" ? ev.decision : "deny";
    let approvalWarning: string | undefined;
    const approvalRequestId = decision === "hold" || decision === "escalate" ? ev.approvalRequestId : undefined;
    if (approvalRequestId !== undefined) {
      // Freeze the refund under its approval, so resuming can only issue this one.
      try {
        await options.ledger.recordPendingApproval({
          approval_request_id: approvalRequestId,
          gate_ref: gateRef,
          actor_id: options.actor,
          environment: options.environment,
          payment_intent: piId,
          amount_cents: amountCents,
          snapshot: { ...snapshot },
          digest,
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
    return { refunded: false, decision: "verify_failed", reason: "permit verified but was not reported consumed", ...evidence };
  }

  try {
    await options.ledger.recordAuthorized({
      gate_ref: gateRef,
      permit_sha256: sha256(ev.permitId),
      audit_hash: ev.auditHash,
      payment_intent: piId,
      amount_cents: amountCents,
      actor_id: options.actor,
      authorized_at: now().toISOString(),
    });
  } catch (err) {
    return { refunded: false, decision: "error", reason: `could not record the permit: ${errorText(err)}`, ...evidence };
  }

  // From here on, every stop cancels the ledger entry.
  const abort = async (decision: StripeRefundBlockReason, reason: string): Promise<StripeRefundDenial> => {
    try {
      await options.ledger.recordAborted(gateRef, decision);
    } catch (err) {
      reason += `; the ledger entry could not be cancelled: ${errorText(err)}`;
    }
    return { refunded: false, decision, reason, ...evidence };
  };

  let current: StripeRefundFacts | null;
  try {
    current = await readFacts(stripe, piId, options, now());
  } catch (err) {
    return abort("error", `could not re-read the payment or order: ${errorText(err)}`);
  }
  if (!stillSupports(current, snapshot, facts.order_status)) {
    return abort("payment_changed", "the payment or order changed after the refund was authorized");
  }

  const metadata: Record<string, string> = { atlasent_gate_ref: gateRef, order_ref: snapshot.order_ref };
  if (request.reason) metadata.atlasent_reason = request.reason.slice(0, 500);

  // ONLY reachable after allow + verified + consumed + recorded + re-read.
  let refund: StripeRefund;
  try {
    refund = await stripe.createRefund(
      { payment_intent: snapshot.payment_intent, amount: snapshot.amount_cents, reason: "requested_by_customer", metadata },
      gateRef,
    );
  } catch (err) {
    // If Stripe did create it (a timeout after commit), the cancelled entry
    // makes the alarm flag it: the safe direction.
    return abort("error", `refund request failed: ${errorText(err)}`);
  }
  if (!ACCEPTED_REFUND_STATUSES.has(refund.status)) {
    return abort("error", `Stripe returned the refund as ${refund.status}`);
  }
  if (refund.payment_intent !== snapshot.payment_intent || refund.charge !== snapshot.charge ||
      refund.amount !== snapshot.amount_cents || refund.currency?.toUpperCase() !== snapshot.currency) {
    return abort("error", "Stripe returned a refund that does not match the authorized action; reconcile before retrying");
  }

  let ledgerWarning: string | undefined;
  try {
    await options.ledger.recordExecuted(gateRef, refund.id);
  } catch (err) {
    ledgerWarning = `refund ${refund.id} ran but the ledger did not record it: ${errorText(err)}`;
  }

  return {
    refunded: true,
    completion: refund.status as StripeRefundSuccess["completion"],
    refund,
    amountCents,
    gateRef,
    auditHash: ev.auditHash,
    digest,
    facts,
    ...(ledgerWarning !== undefined ? { ledgerWarning } : {}),
  };
}

export interface StripeResumeRequest {
  approvalRequestId: string;
  /** Who asked to resume (e.g. the support lead who checked the approval). Recorded, never authorizes. */
  resumedBy?: string;
}

/**
 * Resume an escalated refund after a person decided it in the AtlaSent console.
 *
 * Single-shot (call it again later while the approval is pending):
 *   - pending → `hold`, nothing changes;
 *   - declined, expired, revoked, ... → `deny` (`APPROVAL_<STATUS>`), closed;
 *   - approved → re-read the payment and order (they must still carry the
 *     frozen refund), claim the ONE permit, check it is bound to this
 *     refund's digest, verify (consumed), record it, re-read again, then
 *     POST /v1/refunds with the escalated attempt's gateRef as its
 *     Idempotency-Key.
 *
 * Only a refund this gate escalated and froze can be resumed, and only
 * exactly as it was evaluated. Fail-closed throughout; a stop after the
 * permit is recorded cancels the ledger entry, as in the gate.
 */
export async function resumeApprovedStripeRefund(
  stripe: StripeApi,
  atlasent: AtlaSentClient,
  approvals: ApprovalsApi,
  request: StripeResumeRequest,
  options: StripeRefundGuardOptions,
): Promise<StripeRefundResult> {
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
  const snap = p.snapshot as unknown as StripeRefundSnapshot;
  if (snap.account !== options.account) {
    return { refunded: false, decision: "invalid_request", reason: "that approval request belongs to a different Stripe account", gateRef: "" };
  }
  const resumedBy = request.resumedBy ? ` (resumed by ${request.resumedBy})` : "";
  const finish = async (result: StripeRefundResult, decision: string, reason: string) =>
    emitDecision(result, p.payment_intent, p.amount_cents, options, {
      id,
      decision,
      reason: reason + resumedBy,
      orderRef: typeof snap.order_ref === "string" ? snap.order_ref : null,
      currency: typeof snap.currency === "string" ? snap.currency : null,
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

  // Approved. Before claiming the one permit, the payment must still carry exactly the frozen refund.
  const stop = async (decision: StripeRefundBlockReason, reason: string, facts?: StripeRefundFacts | null) => {
    await close("stopped", reason);
    return finish({ refunded: false, decision, reason, gateRef, approvalRequestId: id, digest: p.digest, ...(facts ? { facts } : {}) }, "approval_stopped", reason);
  };
  let facts: StripeRefundFacts | null;
  try {
    facts = await readFacts(stripe, p.payment_intent, options, now());
  } catch (err) {
    return { refunded: false, decision: "error", reason: `could not read the payment or order: ${errorText(err)}`, gateRef, approvalRequestId: id };
  }
  const same =
    facts !== null &&
    facts.charge !== null &&
    facts.order_ref !== null &&
    bookkeepingProblem(facts, p.amount_cents) === undefined &&
    computeStripeRefundDigest({
      account: options.account,
      payment_intent: facts.payment_intent,
      charge: facts.charge,
      order_ref: facts.order_ref,
      amount_cents: p.amount_cents,
      currency: facts.currency,
    }) === p.digest;
  if (!same || facts === null) {
    return stop("payment_changed", "the payment or order changed after the refund was escalated; the approval does not cover it", facts);
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
      permit_sha256: sha256(claim.permitToken),
      audit_hash: "",
      payment_intent: p.payment_intent,
      amount_cents: p.amount_cents,
      actor_id: p.actor_id,
      authorized_at: now().toISOString(),
    });
  } catch (err) {
    return stop("error", `could not record the permit: ${errorText(err)}`, facts);
  }
  const abort = async (decision: StripeRefundBlockReason, reason: string) => {
    try {
      await options.ledger.recordAborted(gateRef, decision);
    } catch (err) {
      reason += `; the ledger entry could not be cancelled: ${errorText(err)}`;
    }
    return stop(decision, reason, facts);
  };

  let current: StripeRefundFacts | null;
  try {
    current = await readFacts(stripe, p.payment_intent, options, now());
  } catch (err) {
    return abort("error", `could not re-read the payment or order: ${errorText(err)}`);
  }
  if (!stillSupports(current, snap, facts.order_status)) {
    return abort("payment_changed", "the payment or order changed after the refund was approved");
  }

  const metadata: Record<string, string> = { atlasent_gate_ref: gateRef, order_ref: snap.order_ref, atlasent_approval: id };
  if (p.reason) metadata.atlasent_reason = p.reason.slice(0, 500);

  let refund: StripeRefund;
  try {
    refund = await stripe.createRefund(
      { payment_intent: snap.payment_intent, amount: snap.amount_cents, reason: "requested_by_customer", metadata },
      gateRef,
    );
  } catch (err) {
    return abort("error", `refund request failed: ${errorText(err)}`);
  }
  if (!ACCEPTED_REFUND_STATUSES.has(refund.status)) {
    return abort("error", `Stripe returned the refund as ${refund.status}`);
  }
  if (refund.payment_intent !== snap.payment_intent || refund.charge !== snap.charge ||
      refund.amount !== snap.amount_cents || refund.currency?.toUpperCase() !== snap.currency) {
    return abort("error", "Stripe returned a refund that does not match the approved action; reconcile before retrying");
  }
  let ledgerWarning: string | undefined;
  try {
    await options.ledger.recordExecuted(gateRef, refund.id);
  } catch (err) {
    ledgerWarning = `refund ${refund.id} ran but the ledger did not record it: ${errorText(err)}`;
  }
  await close("refunded", refund.id);
  return finish(
    { refunded: true, completion: refund.status as StripeRefundSuccess["completion"], refund, amountCents: p.amount_cents, gateRef, auditHash: "", digest: p.digest, facts, ...(ledgerWarning ? { ledgerWarning } : {}) },
    "allow_after_approval",
    "approved by a manager",
  );
}

