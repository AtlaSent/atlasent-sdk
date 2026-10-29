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
import { isUnresolvedSubmission, type LedgerEntry, type PendingApproval, type PermitLedger, type RefundReservation } from "./ledger.js";
import { CLAIMABLE_APPROVAL_STATUSES, type ApprovalsApi } from "./approvals.js";
import { outcomeOf, REFUND_DECISION_SCHEMA, type RefundDecisionRecord } from "./decision-record.js";
import type { RefundBudgetSubject, RefundReservationsApi } from "./reservations.js";

/** ACT-0024 canonical action: releasing a payment, refund or payout. The default, and what every existing approval is bound to. */
export const FINANCE_PAYMENT_AUTHORIZE = "finance.payment.authorize" as const;

/**
 * The Action Catalog's refund action and the runtime slug orgs on the
 * us-forprofit-baseline product already run (USFP-ACT-008), minted as
 * CANON-000058. Opt in only when the org's
 * installed action class is this slug; the adapter never maps one onto the other.
 */
export const CUSTOMER_REFUND_ISSUE = "customer.refund.issue" as const;

export type RefundActionType = typeof FINANCE_PAYMENT_AUTHORIZE | typeof CUSTOMER_REFUND_ISSUE;
const REFUND_ACTION_TYPES: ReadonlySet<string> = new Set([FINANCE_PAYMENT_AUTHORIZE, CUSTOMER_REFUND_ISSUE]);

/** Folded into the digest; bump when the digest input changes. */
export const STRIPE_REFUND_BINDING_VERSION = "stripe_refund_binding.v1" as const;
/**
 * v2 also binds the action type and the business request id. Used only when
 * either is present, so a v1 digest (every refund and approval before these
 * fields) is computed exactly as before.
 */
export const STRIPE_REFUND_BINDING_VERSION_V2 = "stripe_refund_binding.v2" as const;

/** How long after authorization an unconfirmed refund may be resubmitted with its Idempotency-Key. Stripe keeps keys 24 h; the permit TTL is 1 h. */
export const RESUBMIT_WINDOW_MS = 60 * 60 * 1000;

const BUSINESS_REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;

/** Stripe refund statuses that mean the refund was accepted. */
const ACCEPTED_REFUND_STATUSES = new Set(["succeeded", "pending", "requires_action"]);

export interface StripeRefundRequest {
  paymentIntentId: string;
  /** Whole cents, e.g. 1899 for $18.99. */
  amountCents: number;
  /** Free text recorded in the refund metadata. */
  reason?: string;
  /**
   * The caller's durable id for this one refund (a support ticket and line,
   * a return authorization). 8-128 of `A-Z a-z 0-9 . _ : -`. The gate reference,
   * and so Stripe's Idempotency-Key, is derived from it, so a retry after a lost
   * response is the SAME operation: it is never evaluated or submitted as a new
   * refund. Without it every call is a new operation; do not retry an
   * unconfirmed one that way.
   */
  businessRequestId?: string;
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
  /**
   * The AtlaSent action to evaluate. Default {@link FINANCE_PAYMENT_AUTHORIZE}.
   * Set it to the action the org actually installed; a refund escalated under one
   * action is only ever resumed under that same action.
   */
  actionType?: RefundActionType;
  /** Required for customer.refund.issue. Durable shared exposure, not refund authority. */
  runtimeReservations?: RefundReservationsApi;
}

export interface StripeRefundSnapshot {
  account: string;
  payment_intent: string;
  charge: string;
  order_ref: string;
  amount_cents: number;
  currency: string;
  /** Present only when not finance.payment.authorize (then the digest is v2). */
  action_type?: string;
  /** Present only when the caller gave one (then the digest is v2). */
  business_request_id?: string;
}

function boundOptions(options: StripeRefundGuardOptions): StripeRefundGuardOptions {
  const api = options.runtimeReservations;
  return Object.freeze({ ...options, ...(api ? { runtimeReservations: Object.freeze({
    reserve: api.reserve.bind(api), recheck: api.recheck.bind(api),
  }) } : {}) });
}

export type StripeRefundBlockReason =
  | "deny"
  | "hold"
  | "escalate"
  | "verify_failed"
  | "invalid_request"
  | "payment_changed"
  | "error"
  /** POST /v1/refunds may have created the refund; nobody has confirmed it. Not a failure: reconcile. */
  | "unconfirmed"
  /** This business request already has an operation; nothing new was done. */
  | "duplicate_request"
  /** Another refund on this payment (or this same request) is in flight. */
  | "in_progress";

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
  /** duplicate_request: the refund this business request already produced, when known. */
  existingRefundId?: string;
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
  const v2 = snapshot.action_type !== undefined || snapshot.business_request_id !== undefined;
  const version = v2 ? STRIPE_REFUND_BINDING_VERSION_V2 : STRIPE_REFUND_BINDING_VERSION;
  return sha256(JSON.stringify(sortKeysDeep({ binding_version: version, ...snapshot })));
}

/** The gate reference (and Idempotency-Key) for a business request on one Stripe account. Stable across retries and processes. */
export function gateRefForBusinessRequest(account: string, businessRequestId: string): string {
  return `brq_${sha256(`stripe_refund_business_request.v1\u0000${account}\u0000${businessRequestId}`).slice(0, 40)}`;
}

/** The snapshot's binding fields from the options and request; only non-default values are added (see v2). */
function bindingExtras(actionType: RefundActionType, businessRequestId: string | undefined): Pick<StripeRefundSnapshot, "action_type" | "business_request_id"> {
  return {
    ...(actionType !== FINANCE_PAYMENT_AUTHORIZE ? { action_type: actionType } : {}),
    ...(businessRequestId !== undefined ? { business_request_id: businessRequestId } : {}),
  };
}

/**
 * After a lost response: if a verified event (or readback) already confirmed the
 * submission, return the matching refund read back from Stripe. Never guesses.
 */
async function confirmedMeanwhile(
  stripe: StripeApi,
  ledger: PermitLedger,
  gateRef: string,
  snapshot: StripeRefundSnapshot,
): Promise<StripeRefund | null> {
  try {
    if ((await ledger.get(gateRef))?.submission?.state !== "accepted") return null;
    const tagged = (await stripe.listRefunds(snapshot.payment_intent)).filter((r) => r.metadata?.atlasent_gate_ref === gateRef);
    const r = tagged.length === 1 ? tagged[0]! : null;
    if (r === null || !ACCEPTED_REFUND_STATUSES.has(r.status) || r.amount !== snapshot.amount_cents ||
        r.charge !== snapshot.charge || r.currency?.toUpperCase() !== snapshot.currency) return null;
    return r;
  } catch {
    return null;
  }
}

type SubmissionOutcome =
  | { kind: "accepted"; refund: StripeRefund }
  /** Stripe answered and did not create a matching, live refund. */
  | { kind: "rejected"; reason: string }
  | { kind: "unconfirmed"; reason: string }
  /** The submission state could not be written, so nothing was sent. */
  | { kind: "not_sent"; reason: string };

/**
 * Whether a failed POST /v1/refunds may still have created the refund. Only
 * an HTTP status Stripe documents as not processing the request is definite;
 * a timeout, a lost connection, 409 (concurrent use of the key), 429, 5xx and
 * a 2xx whose body could not be read are all uncertain.
 */
export function submissionErrorIsDefinite(err: unknown): boolean {
  const status = (err as { status?: unknown } | null)?.status;
  return typeof status === "number" && [400, 401, 402, 403, 404].includes(status);
}

/**
 * The one place a refund is created. Records `submitting` before the request
 * (a crash after it leaves the entry unconfirmed, never failed), then the
 * outcome and the provider's own status as an observation.
 */
async function submitRefund(
  stripe: StripeApi,
  ledger: PermitLedger,
  gateRef: string,
  snapshot: StripeRefundSnapshot,
  metadata: Record<string, string>,
  now: () => Date,
  options: StripeRefundGuardOptions,
): Promise<SubmissionOutcome> {
  try {
    await checkRuntimeBudget(stripe, snapshot, options, true);
  } catch {
    return { kind: "not_sent", reason: "shared refund budget refused or unavailable; nothing was submitted" };
  }
  try {
    await ledger.recordSubmission(gateRef, { state: "submitting", at: now().toISOString(), metadata });
  } catch (err) {
    return { kind: "not_sent", reason: `could not record the submission, so the refund was not sent: ${errorText(err)}` };
  }
  const settle = async (state: "accepted" | "rejected" | "unconfirmed", detail: string) => {
    try {
      await ledger.recordSubmission(gateRef, { state, at: now().toISOString(), detail });
    } catch {
      // `submitting` stays on record, which reads as unconfirmed: the safe direction.
    }
  };
  let refund: StripeRefund;
  try {
    refund = await stripe.createRefund(
      { payment_intent: snapshot.payment_intent, amount: snapshot.amount_cents, reason: "requested_by_customer", metadata },
      gateRef,
    );
  } catch (err) {
    if (submissionErrorIsDefinite(err)) {
      await settle("rejected", errorText(err));
      return { kind: "rejected", reason: `refund request failed: ${errorText(err)}` };
    }
    const reason = `the refund request's outcome is unknown (${errorText(err)}); Stripe may have created it. Reconcile with reconcileStripeRefund; do not retry as a new request`;
    await settle("unconfirmed", errorText(err));
    const confirmed = await confirmedMeanwhile(stripe, ledger, gateRef, snapshot);
    return confirmed ? { kind: "accepted", refund: confirmed } : { kind: "unconfirmed", reason };
  }
  if (typeof refund?.id === "string" && typeof refund.status === "string") {
    try {
      await ledger.recordObservation(gateRef, { source: "submission", refund_id: refund.id, status: refund.status, at: now().toISOString() });
    } catch {
      // The observation is evidence, not a control; the outcome below stands.
    }
  }
  if (!ACCEPTED_REFUND_STATUSES.has(refund.status)) {
    await settle("rejected", `returned as ${refund.status}`);
    return { kind: "rejected", reason: `Stripe returned the refund as ${refund.status}` };
  }
  if (refund.payment_intent !== snapshot.payment_intent || refund.charge !== snapshot.charge ||
      refund.amount !== snapshot.amount_cents || refund.currency?.toUpperCase() !== snapshot.currency) {
    // A live refund exists that is not the authorized one. Not rejected: the entry
    // stays open and the payment reserved, and the alarm flags the refund itself.
    await settle("unconfirmed", `mismatch: Stripe returned ${refund.id}, which does not match the authorization`);
    return {
      kind: "unconfirmed",
      reason: `Stripe returned refund ${refund.id}, which does not match the authorized action; treat it as an incident and reconcile before retrying`,
    };
  }
  await settle("accepted", refund.status);
  return { kind: "accepted", refund };
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

/** Re-derive customer identity from Stripe, never caller metadata or options.
 * Reserve is idempotent, including across restarts and approval resumption.
 * No local outcome releases this server-side liability (RF4 remains open). */
async function checkRuntimeBudget(
  stripe: StripeApi, snapshot: StripeRefundSnapshot, options: StripeRefundGuardOptions, recheck: boolean,
): Promise<void> {
  const required = snapshot.action_type === CUSTOMER_REFUND_ISSUE;
  const api = options.runtimeReservations;
  if (!api) { if (required) throw new Error("runtime refund reservations required"); return; }
  if (!snapshot.business_request_id || !BUSINESS_REQUEST_ID.test(snapshot.business_request_id)) {
    throw new Error("durable business request required for shared refund budget");
  }
  const pi = await stripe.getPaymentIntent(snapshot.payment_intent);
  if (!pi || pi.id !== snapshot.payment_intent || pi.currency.toUpperCase() !== snapshot.currency
    || pi.latest_charge?.id !== snapshot.charge) throw new Error("budget payment changed");
  const customer = pi.customer == null ? null : typeof pi.customer === "string" ? pi.customer : pi.customer.id;
  if (customer !== null && (typeof customer !== "string" || !/^cus_[A-Za-z0-9]+$/.test(customer))) {
    throw new Error("budget customer identity unavailable");
  }
  const subject: RefundBudgetSubject = {
    environment: options.environment, provider_account: snapshot.account,
    business_request_id: snapshot.business_request_id, payment_ref: snapshot.payment_intent,
    customer_ref: customer, amount_minor: String(snapshot.amount_cents), currency: snapshot.currency.toLowerCase(),
  };
  const { reservationId } = await api.reserve(subject);
  if (typeof reservationId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(reservationId)) {
    throw new Error("invalid runtime reservation identity");
  }
  if (recheck) await api.recheck(subject, reservationId);
}

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
  options = boundOptions(options);
  request = Object.freeze({ ...request });
  const result = await decideStripeRefund(stripe, atlasent, request, options);
  // A repeat of an existing operation is not a new decision, so it is not logged as one.
  if (!result.refunded && (result.decision === "duplicate_request" || result.decision === "in_progress")) return result;
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

/** A business request that already has a reservation or entry: answer from the record, never evaluate again. */
async function answerExisting(
  ledger: PermitLedger,
  gateRef: string,
  conflict: { reservation?: RefundReservation; entry?: LedgerEntry },
  request: { piId: string; amountCents: number },
): Promise<StripeRefundDenial> {
  const base = { refunded: false as const, gateRef };
  const prior = conflict.entry ?? conflict.reservation;
  if (prior !== undefined && (prior.payment_intent !== request.piId || prior.amount_cents !== request.amountCents)) {
    return { ...base, decision: "invalid_request", reason: "this business request id was already used for a different payment or amount" };
  }
  const entry = conflict.entry;
  if (entry !== undefined) {
    if (entry.refund_id !== undefined || entry.submission?.state === "accepted") {
      return {
        ...base,
        decision: "duplicate_request",
        reason: `this business request was already submitted to Stripe${entry.refund_id ? ` as ${entry.refund_id}` : ""}; read its outcome with reconcileStripeRefund`,
        ...(entry.refund_id ? { existingRefundId: entry.refund_id } : {}),
      };
    }
    if (isUnresolvedSubmission(entry)) {
      return { ...base, decision: "unconfirmed", reason: "this business request's refund was submitted and its outcome is unknown; reconcile with reconcileStripeRefund" };
    }
    return {
      ...base,
      decision: "duplicate_request",
      reason: `this business request was authorized and then stopped (${entry.aborted_reason ?? "no refund issued"}); a new decision needs a new business request id`,
    };
  }
  let pending: PendingApproval | undefined;
  try {
    pending = await ledger.findPendingApprovalByGateRef(gateRef);
  } catch (err) {
    return { ...base, decision: "error", reason: `could not read the pending approval: ${errorText(err)}` };
  }
  if (pending !== undefined && pending.resolved === undefined) {
    return {
      ...base,
      decision: "hold",
      reason: "this business request is waiting for an approval; resume it with resumeApprovedStripeRefund",
      approvalRequestId: pending.approval_request_id,
    };
  }
  return { ...base, decision: "in_progress", reason: "this business request is already being processed" };
}

async function decideStripeRefund(
  stripe: StripeApi,
  atlasent: AtlaSentClient,
  request: StripeRefundRequest,
  options: StripeRefundGuardOptions,
): Promise<StripeRefundResult> {
  const now = options.now ?? (() => new Date());
  const amountCents = request.amountCents;
  const businessRequestId = request.businessRequestId;
  const actionType = options.actionType ?? FINANCE_PAYMENT_AUTHORIZE;
  // Never the permit token: the SDK's evaluationId/permitId IS the token.
  const gateRef = businessRequestId !== undefined && BUSINESS_REQUEST_ID.test(businessRequestId)
    ? gateRefForBusinessRequest(options.account, businessRequestId)
    : randomUUID();
  const invalid = (reason: string, extra: Partial<StripeRefundDenial> = {}): StripeRefundDenial => ({
    refunded: false,
    decision: "invalid_request",
    reason,
    gateRef,
    ...extra,
  });
  if (!Number.isSafeInteger(amountCents) || amountCents <= 0) return invalid("amountCents must be a positive whole number of cents");
  if (businessRequestId !== undefined && !BUSINESS_REQUEST_ID.test(businessRequestId)) {
    return invalid("businessRequestId must be 8-128 characters of A-Z a-z 0-9 . _ : -");
  }
  if (!REFUND_ACTION_TYPES.has(actionType)) return invalid(`unsupported refund action type ${String(actionType)}`);
  if ((actionType === CUSTOMER_REFUND_ISSUE || options.runtimeReservations) &&
    (!options.runtimeReservations || businessRequestId === undefined)) {
    return invalid("canonical/shared-budget refunds require runtimeReservations and a durable businessRequestId");
  }
  let piId: string;
  try {
    piId = assertPaymentIntentId(request.paymentIntentId);
  } catch (err) {
    return invalid(errorText(err));
  }

  // One in-flight refund per payment, and one operation per business request.
  let reserved;
  try {
    reserved = await options.ledger.reserve({
      gate_ref: gateRef,
      payment_intent: piId,
      amount_cents: amountCents,
      ...(businessRequestId !== undefined ? { business_request_id: businessRequestId } : {}),
      created_at: now().toISOString(),
    });
  } catch (err) {
    return { refunded: false, decision: "error", reason: `could not reserve the refund: ${errorText(err)}`, gateRef };
  }
  if (!reserved.reserved) {
    if (reserved.conflict === "same_request") return answerExisting(options.ledger, gateRef, reserved, { piId, amountCents });
    return {
      refunded: false,
      decision: "in_progress",
      reason: "another refund on this payment is in flight or its outcome is unconfirmed; reconcile it first",
      gateRef,
    };
  }

  const result = await runReservedRefund(stripe, atlasent, request, options, { gateRef, piId, amountCents, actionType, now });
  // The reservation outlives this call only while something is genuinely open:
  // an approval that can be resumed, or a submission nobody has confirmed.
  const keep =
    (!result.refunded && result.decision === "unconfirmed") ||
    (!result.refunded && (result.decision === "hold" || result.decision === "escalate") &&
      result.approvalRequestId !== undefined && result.approvalWarning === undefined);
  if (!keep) {
    try {
      await options.ledger.releaseReservation(gateRef, result.refunded ? `accepted:${result.refund.status}` : result.decision);
    } catch (err) {
      // A stuck reservation blocks later refunds on this payment: fail-closed, and say so.
      const warning = `the reservation could not be released, so later refunds on this payment will be refused until it is: ${errorText(err)}`;
      return result.refunded ? { ...result, ledgerWarning: result.ledgerWarning ? `${result.ledgerWarning}; ${warning}` : warning } : { ...result, reason: `${result.reason}; ${warning}` };
    }
  }
  return result;
}

async function runReservedRefund(
  stripe: StripeApi,
  atlasent: AtlaSentClient,
  request: StripeRefundRequest,
  options: StripeRefundGuardOptions,
  ctx: { gateRef: string; piId: string; amountCents: number; actionType: RefundActionType; now: () => Date },
): Promise<StripeRefundResult> {
  const { gateRef, piId, amountCents, actionType, now } = ctx;
  const invalid = (reason: string, extra: Partial<StripeRefundDenial> = {}): StripeRefundDenial => ({
    refunded: false,
    decision: "invalid_request",
    reason,
    gateRef,
    ...extra,
  });

  let facts: StripeRefundFacts | null;
  try {
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
    ...bindingExtras(actionType, request.businessRequestId),
  });
  const digest = computeStripeRefundDigest(snapshot);

  try { await checkRuntimeBudget(stripe, snapshot, options, false); }
  catch { return { refunded: false, decision: "hold", reason: "shared refund budget refused or unavailable", gateRef, digest, facts }; }

  let ev: EvaluateResponse;
  try {
    ev = await atlasent.evaluate({
      actor_id: options.actor,
      action_type: actionType,
      environment: options.environment,
      resource_id: piId,
      execution_payload_hash: digest,
      // The SDK/runtime requires execution environment inside context as well as
      // at the top level. Bind it to the configured gate environment, never
      // to an agent-provided claim; missing/mismatched environment fails closed.
      context: { ...policyContext(facts, amountCents), environment: options.environment },
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
      action: actionType,
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
      action_type: actionType,
      ...(request.businessRequestId !== undefined ? { business_request_id: request.businessRequestId } : {}),
      snapshot: { ...snapshot },
      digest,
      order_status: facts.order_status,
    });
  } catch (err) {
    return { refunded: false, decision: "error", reason: `could not record the permit: ${errorText(err)}`, ...evidence };
  }

  // From here on, every definite stop cancels the ledger entry.
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
  if (request.businessRequestId !== undefined) metadata.atlasent_business_request = request.businessRequestId;

  // ONLY reachable after allow + verified + consumed + recorded + re-read.
  const sent = await submitRefund(stripe, options.ledger, gateRef, snapshot, metadata, now, options);
  if (sent.kind === "unconfirmed") {
    // Not aborted: if Stripe did create it, it is this authorized refund, and the alarm must say so.
    return { refunded: false, decision: "unconfirmed", reason: sent.reason, ...evidence };
  }
  if (sent.kind !== "accepted") return abort("error", sent.reason);
  const refund = sent.refund;

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
  options = boundOptions(options);
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
  // The action the refund was escalated under, never the caller's current setting.
  const actionType = (typeof snap.action_type === "string" ? snap.action_type : FINANCE_PAYMENT_AUTHORIZE) as RefundActionType;
  if (!REFUND_ACTION_TYPES.has(actionType)) {
    return { refunded: false, decision: "invalid_request", reason: `that approval was escalated under an unsupported action ${actionType}`, gateRef };
  }
  if (options.actionType !== undefined && options.actionType !== actionType) {
    return {
      refunded: false,
      decision: "invalid_request",
      reason: `that approval was escalated under ${actionType}, not ${options.actionType}; it can only be resumed under the action it was approved for`,
      gateRef,
      approvalRequestId: id,
    };
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
    if (outcome === "unconfirmed") return; // the payment stays reserved until reconciled
    try {
      await options.ledger.releaseReservation(gateRef, `approval_${outcome}`);
    } catch {
      // Fail-closed: a stuck reservation only refuses later refunds on this payment.
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
      ...(snap.action_type !== undefined ? { action_type: snap.action_type } : {}),
      ...(snap.business_request_id !== undefined ? { business_request_id: snap.business_request_id } : {}),
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
      action: actionType,
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
      action_type: actionType,
      ...(snap.business_request_id !== undefined ? { business_request_id: snap.business_request_id } : {}),
      snapshot: { ...snap },
      digest: p.digest,
      order_status: facts.order_status,
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
  if (typeof snap.business_request_id === "string") metadata.atlasent_business_request = snap.business_request_id;

  const sent = await submitRefund(stripe, options.ledger, gateRef, snap, metadata, now, options);
  if (sent.kind === "unconfirmed") {
    await close("unconfirmed", sent.reason);
    return finish(
      { refunded: false, decision: "unconfirmed", reason: sent.reason, gateRef, approvalRequestId: id, digest: p.digest, facts },
      "approval_unconfirmed",
      "approved; refund outcome unconfirmed",
    );
  }
  if (sent.kind !== "accepted") {
    return abort("error", sent.kind === "rejected" ? sent.reason.replace("authorized action", "approved action") : sent.reason);
  }
  const refund = sent.refund;
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


export type StripeReconcileState =
  | "succeeded"
  | "pending"
  | "requires_action"
  | "failed"
  | "canceled"
  /** Submitted (or possibly submitted) and still not visible in Stripe. Not a failure. */
  | "unconfirmed"
  /** The gate stopped before Stripe created anything, and Stripe shows nothing for it. */
  | "not_issued"
  /** Stripe's record disagrees with the ledger (another amount or payment, two refunds, or none after acceptance). Treat as an incident. */
  | "mismatch"
  /** Stripe could not be read; nothing was concluded. */
  | "read_failed"
  | "unknown_reference";

export interface StripeReconcileResult {
  gateRef: string;
  state: StripeReconcileState;
  reason: string;
  refundId?: string;
  /** True when this call resent POST /v1/refunds with the original Idempotency-Key. */
  resubmitted?: boolean;
}

const PROVIDER_STATES: ReadonlySet<string> = new Set(["succeeded", "pending", "requires_action", "failed", "canceled"]);

/**
 * Read a gated refund's outcome back from Stripe and record it.
 *
 * Looks the refund up by the gate reference it carries in its metadata, never
 * by amount, and records Stripe's status as a `readback` observation. An
 * unconfirmed submission that Stripe does not show stays unconfirmed, unless
 * `resubmit` is set: then, within {@link RESUBMIT_WINDOW_MS} of authorization
 * and only if the payment and order still carry exactly the authorized refund,
 * POST /v1/refunds is sent again with the SAME Idempotency-Key and the SAME
 * parameters. Stripe returns the original refund if the first request created
 * it, so this is the one authorized operation, not a new one. It never
 * evaluates, and never uses a new key.
 */
export async function reconcileStripeRefund(
  stripe: StripeApi,
  gateRef: string,
  options: StripeRefundGuardOptions,
  opts: { resubmit?: boolean } = {},
): Promise<StripeReconcileResult> {
  options = boundOptions(options);
  const now = options.now ?? (() => new Date());
  const ledger = options.ledger;
  const out = (state: StripeReconcileState, reason: string, extra: Partial<StripeReconcileResult> = {}): StripeReconcileResult => ({
    gateRef,
    state,
    reason,
    ...extra,
  });
  let entry: LedgerEntry | undefined;
  try {
    entry = await ledger.get(gateRef);
  } catch (err) {
    return out("read_failed", `the ledger could not be read: ${errorText(err)}`);
  }
  if (entry === undefined) return out("unknown_reference", "the gate never authorized this reference");
  const e = entry;

  let history: StripeRefund[];
  try {
    history = await stripe.listRefunds(e.payment_intent);
  } catch (err) {
    return out("read_failed", `Stripe's refund history could not be read: ${errorText(err)}`);
  }
  const tagged = history.filter((r) => r.metadata?.atlasent_gate_ref === gateRef);
  const snap = e.snapshot as Partial<StripeRefundSnapshot> | undefined;

  const settle = async (refund: StripeRefund, source: "readback" | "submission"): Promise<StripeReconcileResult> => {
    const notes: string[] = [];
    const tryWrite = async (what: string, op: () => Promise<void>) => {
      try {
        await op();
      } catch (err) {
        notes.push(`${what} not recorded: ${errorText(err)}`);
      }
    };
    if (source === "readback") {
      await tryWrite("observation", () => ledger.recordObservation(gateRef, { source, refund_id: refund.id, status: refund.status, at: now().toISOString() }));
    }
    if (e.refund_id === undefined) await tryWrite("refund id", () => ledger.recordExecuted(gateRef, refund.id));
    if (isUnresolvedSubmission(e)) {
      await tryWrite("submission", () => ledger.recordSubmission(gateRef, { state: "accepted", at: now().toISOString(), detail: `confirmed by ${source}: ${refund.status}` }));
    }
    await tryWrite("reservation release", () => ledger.releaseReservation(gateRef, `reconciled:${refund.status}`));
    const state: StripeReconcileState = PROVIDER_STATES.has(refund.status) ? (refund.status as StripeReconcileState) : "unconfirmed";
    const reason = PROVIDER_STATES.has(refund.status) ? `Stripe reports ${refund.status}` : `Stripe reports an unrecognized status ${refund.status}`;
    return out(state, notes.length ? `${reason}; ${notes.join("; ")}` : reason, { refundId: refund.id });
  };

  if (tagged.length > 1) return out("mismatch", `Stripe holds ${tagged.length} refunds carrying this gate reference`);
  if (tagged.length === 1) {
    const r = tagged[0]!;
    const matches =
      e.aborted_reason === undefined &&
      r.payment_intent === e.payment_intent &&
      r.amount === e.amount_cents &&
      (e.refund_id === undefined || e.refund_id === r.id) &&
      (snap?.charge === undefined || r.charge === snap.charge) &&
      (snap?.currency === undefined || r.currency?.toUpperCase() === snap.currency);
    if (!matches) {
      return out("mismatch", e.aborted_reason !== undefined
        ? `Stripe holds refund ${r.id} for a reference the gate stopped (${e.aborted_reason})`
        : `Stripe's refund ${r.id} does not match the authorized refund`, { refundId: r.id });
    }
    return settle(r, "readback");
  }

  if (e.aborted_reason !== undefined) return out("not_issued", `the gate stopped before issuing it (${e.aborted_reason}) and Stripe shows no refund for it`);
  if (e.refund_id !== undefined || e.submission?.state === "accepted") {
    return out("mismatch", "the ledger records an accepted refund, but Stripe shows none carrying this gate reference");
  }
  if (!opts.resubmit) return out("unconfirmed", "Stripe shows no refund for this reference yet; read again later, or resubmit with the same key");

  // Resubmission: the one authorized refund, same key, same parameters, re-checked first.
  const meta = e.submission?.metadata;
  const authorizedAt = Date.parse(e.authorized_at);
  if (snap === undefined || e.digest === undefined || meta === undefined || e.order_status === undefined) {
    return out("unconfirmed", "this entry predates resubmission records; an operator must reconcile it in Stripe");
  }
  if (!Number.isFinite(authorizedAt) || now().getTime() - authorizedAt > RESUBMIT_WINDOW_MS || now().getTime() < authorizedAt) {
    return out("unconfirmed", "the resubmission window has passed; an operator must reconcile it in Stripe, and any new refund needs a new decision");
  }
  let current: StripeRefundFacts | null;
  try {
    current = await readFacts(stripe, e.payment_intent, options, now());
  } catch (err) {
    return out("unconfirmed", `could not re-read the payment or order, so nothing was resent: ${errorText(err)}`);
  }
  const snapshot = snap as StripeRefundSnapshot;
  if (!stillSupports(current, snapshot, e.order_status) || computeStripeRefundDigest(snapshot) !== e.digest || snapshot.account !== options.account) {
    return out("unconfirmed", "the payment or order no longer carries exactly the authorized refund, so it was not resent; an operator must reconcile it");
  }
  const sent = await submitRefund(stripe, ledger, gateRef, snapshot, meta, now, options);
  if (sent.kind === "accepted") return { ...(await settle(sent.refund, "submission")), resubmitted: true };
  if (sent.kind === "unconfirmed") return out("unconfirmed", sent.reason, { resubmitted: true });
  if (sent.kind === "not_sent") return out("unconfirmed", sent.reason);
  try {
    await ledger.recordAborted(gateRef, "rejected_on_resubmission");
    await ledger.releaseReservation(gateRef, "rejected_on_resubmission");
  } catch (err) {
    return out("not_issued", `${sent.reason}; the ledger was not updated: ${errorText(err)}`, { resubmitted: true });
  }
  return out("not_issued", sent.reason, { resubmitted: true });
}
