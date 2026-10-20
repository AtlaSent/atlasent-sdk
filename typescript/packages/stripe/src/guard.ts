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
import type { PermitLedger } from "./ledger.js";
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
  digest?: string;
  facts?: StripeRefundFacts;
  logWarning?: string;
}

export interface StripeRefundSuccess {
  refunded: true;
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

async function readFacts(
  stripe: StripeApi,
  piId: string,
  options: StripeRefundGuardOptions,
  now: Date,
): Promise<StripeRefundFacts | null> {
  const pi = await stripe.getPaymentIntent(piId);
  if (pi === null) return null;
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
  if (options.onDecision === undefined) return result;
  const facts = result.facts;
  const record: RefundDecisionRecord = {
    schema: REFUND_DECISION_SCHEMA,
    at: (options.now ?? (() => new Date()))().toISOString(),
    system: "stripe",
    gate_ref: result.gateRef,
    actor: options.actor,
    environment: options.environment,
    target: facts?.payment_intent ?? request.paymentIntentId,
    order_ref: facts?.order_ref ?? null,
    amount_cents: Number.isSafeInteger(request.amountCents) ? request.amountCents : null,
    currency: facts?.currency ?? null,
    outcome: outcomeOf(result.refunded, result.refunded ? "allow" : result.decision),
    decision: result.refunded ? "allow" : result.decision,
    deny_code: result.refunded ? null : (result.denyCode ?? null),
    reason: result.refunded ? "within policy" : result.reason,
    audit_hash: result.auditHash || null,
    refund_id: result.refunded ? result.refund.id : null,
    order_status: facts?.order_status ?? null,
    days_since_delivery: facts?.days_since_delivery ?? null,
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
  if (
    current === null ||
    !current.payment_succeeded ||
    current.disputed ||
    current.charge !== snapshot.charge ||
    current.order_ref !== snapshot.order_ref ||
    current.order_status !== facts.order_status ||
    current.refundable_cents < amountCents
  ) {
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
