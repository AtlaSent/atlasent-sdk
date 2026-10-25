import { describe, expect, it } from "vitest";
import {
  inspectCollectedRefundEvidence, REFUND_EVIDENCE_KINDS,
  type CollectedRefundEvidence, type RefundEvidenceScope,
} from "../src/trusted-evidence.js";

const scope: RefundEvidenceScope = {
  organization_id: "org_a", processor_account_id: "acct_a", environment: "test",
  payment_intent_id: "pi_123", order_id: "order_1", customer_id: "cus_1", refund_case_id: "case_1",
};
const now = new Date("2026-10-25T12:00:00Z");
const records = (): CollectedRefundEvidence[] => REFUND_EVIDENCE_KINDS.map(kind => ({
  kind, scope: { ...scope }, source_system: "merchant-server", source_record_id: `record-${kind}`,
  record_digest: "a".repeat(64), observed_at: "2026-10-25T11:59:00Z", status: "available",
}));
const inspect = (r: CollectedRefundEvidence[], expected = scope) => inspectCollectedRefundEvidence(r, expected, now, 300000);
describe("collected refund source readiness is never authorization", () => {
  it("reports complete structure but never claims trusted provenance or authority", () => {
    const result = inspect(records());
    expect(result.structurally_complete).toBe(true);
    expect(result.sources_authenticated).toBe(false);
    expect(result.authority_verified).toBe(false);
    expect(result.ready_to_authorize).toBe(false);
  });
  it("requires all seven evidence kinds and refuses missing sources", () => {
    const result = inspect(records().slice(0, -1));
    expect(result.structurally_complete).toBe(false);
    expect(result.missing).toEqual(["processor_outcome"]);
  });
  it("rejects cross-tenant, cross-account and changed refund case", () => {
    for (const key of ["organization_id", "processor_account_id", "refund_case_id"] as const) {
      const r = records();
      r[0]!.scope[key] = "other";
      expect(inspect(r).defects.some(x => x.includes(`${key} scope mismatch`))).toBe(true);
    }
  });
  it("rejects duplicate source kinds and unavailable evidence", () => {
    const r = records();
    r.push({ ...r[0]! });
    r[1]!.status = "unavailable";
    const result = inspect(r);
    expect(result.defects.some(x => x.includes("duplicate kind"))).toBe(true);
    expect(result.defects.some(x => x.includes("source unavailable"))).toBe(true);
  });
  it("rejects stale/future/malformed timestamps, missing digests and source identity", () => {
    const r = records();
    r[0]!.observed_at = "2026-10-25T11:00:00Z";
    r[1]!.observed_at = "2026-10-25T12:01:00Z";
    r[2]!.observed_at = "not-a-time";
    r[3]!.record_digest = "unknown";
    r[4]!.source_system = "";
    const result = inspect(r);
    expect(result.structurally_complete).toBe(false);
    expect(result.defects.filter(x => x.includes("source observation")).length).toBe(3);
    expect(result.defects.some(x => x.includes("source digest"))).toBe(true);
    expect(result.defects.some(x => x.includes("source identity"))).toBe(true);
  });
  it("rejects invalid clocks and age policy rather than assuming fresh", () => {
    expect(inspectCollectedRefundEvidence(records(), scope, new Date("invalid"), 300000).structurally_complete).toBe(false);
    expect(inspectCollectedRefundEvidence(records(), scope, now, 0).structurally_complete).toBe(false);
  });
});
