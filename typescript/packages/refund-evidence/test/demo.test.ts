/**
 * The one-command demo, end to end: the real Shopify and Stripe gate code and
 * the agent's refund tool, over simulated stores and the local policy
 * stand-in, ending in the evidence report.
 */

import { describe, expect, it } from "vitest";
import { runDemo } from "../src/demo.js";
import { parseLog } from "../src/records.js";
import { createSimulatedRuntime, simulatedRuntime } from "../src/sim.js";

const NOW = new Date("2026-10-20T12:00:00Z");

describe("runDemo", () => {
  const run = () => {
    const sim = createSimulatedRuntime();
    return runDemo({ atlasent: sim.client, simulatedDecisions: true, environment: "test", now: () => NOW, manager: sim });
  };

  it("one policy decides refunds on Shopify, Stripe and the agent's tool, and catches both bypasses", async () => {
    const r = await run();

    expect(r.decisions.map((d) => [d.system, d.order_ref, d.amount_cents, d.outcome, d.deny_code, d.actor.split(":")[0]])).toEqual([
      ["shopify", "#PPS-1001", 1899, "refunded", null, "shopify-staff"],
      ["shopify", "#PPS-1002", 7200, "escalated", "MANAGER_APPROVAL_REQUIRED", "shopify-staff"],
      ["shopify", "#PPS-1003", 1200, "denied", "ORDER_NOT_DELIVERED", "shopify-staff"],
      ["shopify", "#PPS-1004", 2500, "denied", "RETURN_WINDOW_EXPIRED", "shopify-staff"],
      ["shopify", "#PPS-1005", 1999, "refunded", null, "agent"],
      ["stripe", "PPS-2001", 2900, "refunded", null, "support-tool"],
      ["stripe", "PPS-2002", 8500, "escalated", "MANAGER_APPROVAL_REQUIRED", "support-tool"],
      // The manager approves the Shopify escalation and declines the Stripe one.
      ["shopify", "#PPS-1002", 7200, "refunded", null, "shopify-staff"],
      ["stripe", "PPS-2002", 8500, "denied", "APPROVAL_DENIED", "support-tool"],
    ]);
    const [approved, declined] = r.decisions.slice(7);
    expect(approved).toMatchObject({ decision: "allow_after_approval", approval_request_id: r.decisions[1]!.approval_request_id });
    expect(declined).toMatchObject({ decision: "approval_not_granted", approval_request_id: r.decisions[6]!.approval_request_id });
    expect(r.report.html).toContain("Approved by a manager");
    expect(r.report.html).toContain("Manager did not approve (APPROVAL_DENIED)");

    // Another customer's order never reaches the gate.
    expect(r.agentOwnershipRefusal).toMatch(/No order with that number/);

    // Four gated refunds matched (one approved by a manager); the admin and Dashboard refunds are flagged.
    expect(r.alarms.filter((a) => a.verdict === "authorized")).toHaveLength(4);
    expect(r.alarms.filter((a) => a.verdict === "unauthorized").map((a) => [a.system, a.target, a.amount_cents])).toEqual([
      ["shopify", "gid://shopify/Order/1004", 2500],
      ["stripe", "pi_2002", 8500],
    ]);

    expect(r.report.summary).toMatchObject({
      refunded: { count: 4, cents: { USD: 1899 + 1999 + 2900 + 7200 } },
      approvedByManager: 1,
      escalated: { count: 2 },
      declined: { count: 3 },
      outsideGate: { count: 2, cents: { USD: 2500 + 8500 } },
    });
    expect(r.report.html).toContain("SIMULATED DATA");
  });

  it("without a manager (the real runtime), escalations are left waiting and nothing is resumed", async () => {
    const lines: string[] = [];
    const r = await runDemo({ atlasent: simulatedRuntime(), simulatedDecisions: true, environment: "test", now: () => NOW, log: (l) => lines.push(l) });
    expect(r.decisions).toHaveLength(7);
    expect(r.decisions.filter((d) => d.decision.includes("approval"))).toEqual([]);
    expect(lines.join("\n")).toMatch(/resume --approval/);
  });

  it("never writes a permit token into the log or the report", async () => {
    const r = await run();
    const everything = JSON.stringify(r.decisions) + JSON.stringify(r.alarms) + r.report.html + r.report.csv;
    expect(everything).not.toContain("pt.sim");
  });

  it("its records round-trip through the JSONL log format", async () => {
    const r = await run();
    const parsed = parseLog([...r.decisions, ...r.alarms].map((x) => JSON.stringify(x)).join("\n"));
    expect(parsed.rejectedLines).toEqual([]);
    expect(parsed.decisions).toHaveLength(9);
    expect(parsed.alarms).toHaveLength(6);
  });
});
