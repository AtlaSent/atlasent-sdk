/**
 * The one-command demo, end to end: the real Shopify and Stripe gate code and
 * the agent's refund tool, over simulated stores and the local policy
 * stand-in, ending in the evidence report.
 */

import { describe, expect, it } from "vitest";
import { runDemo } from "../src/demo.js";
import { parseLog } from "../src/records.js";
import { simulatedRuntime } from "../src/sim.js";

const NOW = new Date("2026-10-20T12:00:00Z");

describe("runDemo", () => {
  it("one policy decides refunds on Shopify, Stripe and the agent's tool, and catches both bypasses", async () => {
    const r = await runDemo({ atlasent: simulatedRuntime(), simulatedDecisions: true, environment: "test", now: () => NOW });

    expect(r.decisions.map((d) => [d.system, d.order_ref, d.amount_cents, d.outcome, d.deny_code, d.actor.split(":")[0]])).toEqual([
      ["shopify", "#PPS-1001", 1899, "refunded", null, "shopify-staff"],
      ["shopify", "#PPS-1002", 7200, "escalated", "MANAGER_APPROVAL_REQUIRED", "shopify-staff"],
      ["shopify", "#PPS-1003", 1200, "denied", "ORDER_NOT_DELIVERED", "shopify-staff"],
      ["shopify", "#PPS-1004", 2500, "denied", "RETURN_WINDOW_EXPIRED", "shopify-staff"],
      ["shopify", "#PPS-1005", 1999, "refunded", null, "agent"],
      ["stripe", "PPS-2001", 2900, "refunded", null, "support-tool"],
      ["stripe", "PPS-2002", 8500, "escalated", "MANAGER_APPROVAL_REQUIRED", "support-tool"],
    ]);

    // Another customer's order never reaches the gate.
    expect(r.agentOwnershipRefusal).toMatch(/No order with that number/);

    // Three gated refunds matched; the admin and Dashboard refunds are flagged.
    expect(r.alarms.filter((a) => a.verdict === "authorized")).toHaveLength(3);
    expect(r.alarms.filter((a) => a.verdict === "unauthorized").map((a) => [a.system, a.amount_cents])).toEqual([
      ["shopify", 7200],
      ["stripe", 8500],
    ]);

    expect(r.report.summary).toMatchObject({
      refunded: { count: 3, cents: { USD: 1899 + 1999 + 2900 } },
      escalated: { count: 2 },
      declined: { count: 2 },
      outsideGate: { count: 2, cents: { USD: 15700 } },
    });
    expect(r.report.html).toContain("SIMULATED DATA");
  });

  it("never writes a permit token into the log or the report", async () => {
    const r = await runDemo({ atlasent: simulatedRuntime(), simulatedDecisions: true, environment: "test", now: () => NOW });
    const everything = JSON.stringify(r.decisions) + JSON.stringify(r.alarms) + r.report.html + r.report.csv;
    expect(everything).not.toContain("pt.sim");
  });

  it("its records round-trip through the JSONL log format", async () => {
    const r = await runDemo({ atlasent: simulatedRuntime(), simulatedDecisions: true, environment: "test", now: () => NOW });
    const parsed = parseLog([...r.decisions, ...r.alarms].map((x) => JSON.stringify(x)).join("\n"));
    expect(parsed.rejectedLines).toEqual([]);
    expect(parsed.decisions).toHaveLength(7);
    expect(parsed.alarms).toHaveLength(5);
  });
});
