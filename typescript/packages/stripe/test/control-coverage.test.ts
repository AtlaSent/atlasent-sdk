import { describe, expect, it } from "vitest";
import { buildRefundControlCoverage, REFUND_CONTROL_IDS, type ExecutionAcceptanceInput } from "../src/control-coverage.js";

const valid = (): ExecutionAcceptanceInput => ({
  truth_label: "stripe_test_mode_synthetic",
  run_id: "gha-test",
  atlasent_base_url: "https://lwnqpmnxpeyhpxvastku.supabase.co/functions/v1",
  atlasent_environment: "test",
  action_type: "finance.payment.authorize",
  adapter_revision: "abc123",
  cases: ["A1", "A2", "A3", "A4", "A5", "A6"].map(id => ({ id, verdict: "pass" })),
  summary: { pass: 6, fail: 0, blocked: 0, total: 6 },
});
describe("14-control evidence-limited refund coverage", () => {
  it("records exactly 14 controls, zero fully verified and five partial after six passing TEST cases", () => {
    const r = buildRefundControlCoverage(valid());
    expect(r.controls.map(x => x.id)).toEqual([...REFUND_CONTROL_IDS]);
    expect(r.summary).toEqual({ fully_verified: 0, partial: 5, not_verified: 9, total: 14 });
    expect(r.production_ready).toBe(false);
    expect(r.controls.find(c => c.id === "authority")).toMatchObject({ status: "not_verified", case_ids: [] });
    expect(r.controls.find(c => c.id === "exact-execution")).toMatchObject({ status: "partial", case_ids: ["A1", "A2", "A3", "A4", "A5", "A6"] });
  });
  for (const [label, patch] of [
    ["failed case", { cases: [{ id: "A1", verdict: "fail" }] }],
    ["duplicated case", { cases: Array(6).fill({ id: "A1", verdict: "pass" }) }],
    ["wrong host", { atlasent_base_url: "https://production.example/functions/v1" }],
    ["wrong environment", { atlasent_environment: "production" }],
    ["canonical action not tested", { action_type: "customer.refund.issue" }],
    ["untrusted truth label", { truth_label: "production" }],
    ["false success summary", { summary: { pass: 5, fail: 1, blocked: 0, total: 6 } }],
  ] as const) {
    it(`never grants partial coverage for ${label}`, () => {
      const r = buildRefundControlCoverage({ ...valid(), ...patch });
      expect(r.source_qualifies).toBe(false);
      expect(r.summary).toEqual({ fully_verified: 0, partial: 0, not_verified: 14, total: 14 });
    });
  }
});
