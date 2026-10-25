/**
 * Evidence-limited rollforward for the 14 refund-controls.v1 catalog areas.
 * Six Stripe TEST cases are NOT fourteen business-control acceptance tests.
 * No output from this module may mark a control fully accepted or activate a policy.
 */
export const REFUND_CONTROL_IDS = [
  "transaction-match", "payment-state", "dispute-state", "prior-compensation",
  "amount-allocation", "eligibility", "return-evidence", "authority",
  "budgets", "freshness", "exact-execution", "funding", "completion", "coverage",
] as const;
export type RefundControlId = typeof REFUND_CONTROL_IDS[number];
export type CoverageStatus = "partial" | "not_verified";

export interface ExecutionAcceptanceInput {
  truth_label: string;
  run_id: string;
  atlasent_base_url: string;
  atlasent_environment: string;
  action_type: string;
  adapter_revision: string;
  cases: Array<{ id: string; verdict: string }>;
  summary: { pass: number; fail: number; blocked: number; total: number };
}

const CASES = ["A1", "A2", "A3", "A4", "A5", "A6"] as const;
const CASE_EVIDENCE: Partial<Record<RefundControlId, readonly string[]>> = {
  "transaction-match": ["A1", "A3"],
  "payment-state": ["A1"],
  budgets: ["A4"],
  "exact-execution": ["A1", "A2", "A3", "A4", "A5", "A6"],
  completion: ["A1", "A5", "A6"],
};
const LIMITATIONS: Record<RefundControlId, string> = {
  "transaction-match": "Processor payment/amount binding only; customer and authoritative order ownership unverified",
  "payment-state": "Succeeded synthetic card payments only; failed, uncaptured and reversed states not covered",
  "dispute-state": "Chargeback, inquiry and later-dispute transitions not exercised",
  "prior-compensation": "Credit, gift card, manual compensation and paginated pending refund histories not exercised",
  "amount-allocation": "Line quantities, tax, shipping, discounts, currency precision and entitlement not exercised",
  eligibility: "Versioned merchant reason-specific eligibility not authenticated",
  "return-evidence": "Warehouse receipt, inspection and service-use evidence not authenticated",
  authority: "Verified actor, independent reviewer, revoked grant and exact-approval scope not exercised",
  budgets: "Only one in-flight request per payment tested; cumulative actor/customer/period budgets unverified",
  freshness: "Policy revision, source timestamps and changed conditions after approval unverified",
  "exact-execution": "Idempotency, exact amount and concurrency tested; other credentials and execution paths unverified",
  funding: "Provider funding sufficiency and pending balance not tested",
  completion: "Provider readback tested; signed webhook events, accounting and tax reconciliation unverified",
  coverage: "No inventory or prevention proof for dashboard, supervisor and alternate API paths",
};

export function buildRefundControlCoverage(input: ExecutionAcceptanceInput) {
  const byId = new Map(input.cases.map(c => [c.id, c.verdict]));
  const complete = input.cases.length === CASES.length &&
    byId.size === CASES.length &&
    CASES.every(id => byId.get(id) === "pass") &&
    input.summary.pass === CASES.length &&
    input.summary.fail === 0 && input.summary.blocked === 0 &&
    input.summary.total === CASES.length &&
    input.truth_label === "stripe_test_mode_synthetic" &&
    input.atlasent_environment === "test" &&
    input.action_type === "finance.payment.authorize" &&
    /^https:\/\/lwnqpmnxpeyhpxvastku\.supabase\.co\/functions\/v1\/?$/.test(input.atlasent_base_url);
  const controls = REFUND_CONTROL_IDS.map(id => {
    const cases = complete ? (CASE_EVIDENCE[id] ?? []) : [];
    const status: CoverageStatus = cases.length ? "partial" : "not_verified";
    return { id, status, case_ids: [...cases], limitation: LIMITATIONS[id] };
  });
  return {
    schema: "atlasent.refund_controls_coverage.v1",
    source_run_id: input.run_id,
    adapter_revision: input.adapter_revision,
    source_qualifies: complete,
    scope: "Stripe TEST synthetic payments, AtlaSent staging, legacy finance.payment.authorize only",
    controls,
    summary: {
      fully_verified: 0,
      partial: controls.filter(c => c.status === "partial").length,
      not_verified: controls.filter(c => c.status === "not_verified").length,
      total: controls.length,
    },
    production_ready: false,
    note: "No catalog control is fully accepted by this six-case execution run. Source authenticity, organizational authority and all execution paths require separate evidence.",
  };
}
