import { describe, expect, it } from "vitest";
import { fakeRuntime } from "./fakes.js";

describe("refund authority binding at the runtime verification boundary", () => {
  it("rejects changed actor, action, environment, and digest without consuming the valid permit", async () => {
    const runtime = fakeRuntime();
    const digest = "a".repeat(64);
    const evaluation = await runtime.client.evaluate({
      actor_id: "support-tool:operator",
      action_type: "customer.refund.issue",
      environment: "test",
      execution_payload_hash: digest,
      context: { environment: "test", amount_cents: 100, order_status: "delivered", days_since_delivery: 1 },
    });
    expect(evaluation.decision).toBe("allow");
    const base = { permitId: evaluation.permitId, agent: "support-tool:operator", action: "customer.refund.issue", environment: "test", execution_hash: digest };
    for (const change of [
      { agent: "support-tool:another" },
      { action: "finance.payment.authorize" },
      { environment: "production" },
      { execution_hash: "b".repeat(64) },
    ]) {
      const result = await runtime.client.verifyPermit({ ...base, ...change });
      expect(result.verified).toBe(false);
      expect(result.consumed).not.toBe(true);
    }
    const correct = await runtime.client.verifyPermit(base);
    expect(correct.verified).toBe(true);
    expect(correct.consumed).toBe(true);
    const replay = await runtime.client.verifyPermit(base);
    expect(replay.verified).toBe(false);
  });
  it("does not treat caller-provided approval flags as an authority source", async () => {
    const runtime = fakeRuntime({ forceDecision: "deny" });
    const result = await runtime.client.evaluate({
      actor_id: "agent:refund",
      action_type: "customer.refund.issue",
      environment: "test",
      context: { environment: "test", amount_cents: 100, order_status: "delivered", days_since_delivery: 1, approvals: ["approved"], verified_actor: true },
    });
    expect(result.decision).toBe("deny");
    expect(runtime.permits.size).toBe(0);
  });
});
