/**
 * One record per refund decision, for the evidence report.
 *
 * Schema `atlasent.refund_decision.v1`. The Shopify and Stripe gates each
 * carry this same definition so the packages stay independent; the report
 * (@atlasent/refund-evidence) reads the format, not the packages. Change it
 * only by adding fields, or bump the schema version in all three.
 */

export const REFUND_DECISION_SCHEMA = "atlasent.refund_decision.v1" as const;

export type RefundOutcome = "refunded" | "escalated" | "held" | "denied" | "stopped" | "refused";

export interface RefundDecisionRecord {
  schema: typeof REFUND_DECISION_SCHEMA;
  /** ISO time the gate finished deciding. */
  at: string;
  system: "shopify" | "stripe";
  gate_ref: string;
  actor: string;
  environment: string;
  /** Order gid (Shopify) or PaymentIntent id (Stripe). */
  target: string;
  /** The store's order reference, when known. */
  order_ref: string | null;
  /** Null when the request's amount was not a whole number of cents. */
  amount_cents: number | null;
  currency: string | null;
  outcome: RefundOutcome;
  /** The gate's own decision word (deny, escalate, verify_failed, ...). */
  decision: string;
  deny_code: string | null;
  reason: string;
  /** AtlaSent's audit reference for the evaluation, when it got that far. */
  audit_hash: string | null;
  refund_id: string | null;
  order_status: string | null;
  days_since_delivery: number | null;
  /** The approval request behind an escalation, or behind a refund a manager approved. Absent in records written before approvals. */
  approval_request_id?: string | null;
}

export function outcomeOf(refunded: boolean, decision: string): RefundOutcome {
  if (refunded) return "refunded";
  if (decision === "escalate") return "escalated";
  if (decision === "hold") return "held";
  if (decision === "deny") return "denied";
  if (decision === "invalid_request") return "refused";
  return "stopped";
}
