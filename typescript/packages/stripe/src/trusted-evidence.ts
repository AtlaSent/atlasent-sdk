/**
 * Server-side refund evidence intake contract. Structural validation ONLY:
 * it cannot authenticate a source, validate signatures, approve an actor,
 * prove a business rule, or issue a permit. The future runtime collector must
 * authenticate every source and bind it to the org and exact refund.
 */
export const REFUND_EVIDENCE_KINDS = [
  "order_customer", "return_or_service", "allocation", "prior_compensation",
  "merchant_policy", "cumulative_budget", "processor_outcome",
] as const;
export type RefundEvidenceKind = typeof REFUND_EVIDENCE_KINDS[number];
export interface RefundEvidenceScope {
  organization_id: string;
  processor_account_id: string;
  environment: string;
  payment_intent_id: string;
  order_id: string;
  customer_id: string;
  refund_case_id: string;
}
export interface CollectedRefundEvidence {
  kind: RefundEvidenceKind;
  scope: RefundEvidenceScope;
  source_system: string;
  source_record_id: string;
  /** SHA-256 of canonical source payload; a digest alone does NOT authenticate provenance. */
  record_digest: string;
  observed_at: string;
  status: "available" | "unavailable";
}
export interface EvidenceReadiness {
  structurally_complete: boolean;
  missing: RefundEvidenceKind[];
  defects: string[];
  authority_verified: false;
  sources_authenticated: false;
  ready_to_authorize: false;
}

const SCOPE_KEYS: readonly (keyof RefundEvidenceScope)[] = [
  "organization_id", "processor_account_id", "environment", "payment_intent_id",
  "order_id", "customer_id", "refund_case_id",
];

/** No caller/agent-supplied "approved", "trusted" or "allow" flag is consulted. */
export function inspectCollectedRefundEvidence(
  records: readonly CollectedRefundEvidence[],
  expected: RefundEvidenceScope,
  now: Date,
  maxAgeMs: number,
): EvidenceReadiness {
  const defects: string[] = [];
  const seen = new Set<RefundEvidenceKind>();
  const nowMs = now.getTime();
  if (!Number.isFinite(nowMs) || !Number.isSafeInteger(maxAgeMs) || maxAgeMs <= 0) {
    return { structurally_complete: false, missing: [...REFUND_EVIDENCE_KINDS], defects: ["invalid evidence clock or age policy"], authority_verified: false, sources_authenticated: false, ready_to_authorize: false };
  }
  for (const key of SCOPE_KEYS) {
    if (typeof expected[key] !== "string" || !expected[key].trim()) defects.push(`missing expected scope: ${key}`);
  }
  for (const [index, record] of records.entries()) {
    const prefix = `record[${index}]`;
    if (!record || !REFUND_EVIDENCE_KINDS.includes(record.kind)) {
      defects.push(`${prefix}: unknown evidence kind`);
      continue;
    }
    if (seen.has(record.kind)) defects.push(`${prefix}: duplicate kind ${record.kind}`);
    seen.add(record.kind);
    for (const key of SCOPE_KEYS) {
      if (record.scope?.[key] !== expected[key] || !record.scope?.[key]) defects.push(`${prefix}: ${key} scope mismatch`);
    }
    if (record.status !== "available") defects.push(`${prefix}: source unavailable`);
    if (!record.source_system?.trim() || !record.source_record_id?.trim()) defects.push(`${prefix}: source identity missing`);
    if (!/^[0-9a-f]{64}$/i.test(record.record_digest ?? "")) defects.push(`${prefix}: missing/invalid source digest`);
    const time = Date.parse(record.observed_at ?? "");
    if (!Number.isFinite(time) || time > nowMs || nowMs - time > maxAgeMs) defects.push(`${prefix}: stale/future/invalid source observation`);
  }
  const missing = REFUND_EVIDENCE_KINDS.filter(k => !seen.has(k));
  return {
    structurally_complete: defects.length === 0 && missing.length === 0,
    missing,
    defects,
    authority_verified: false,
    sources_authenticated: false,
    ready_to_authorize: false,
  };
}
