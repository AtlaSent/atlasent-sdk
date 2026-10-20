/**
 * The support agent against a scripted Claude: each test feeds the responses
 * the model would return and checks what the tools let through. No network.
 */

import { describe, expect, it } from "vitest";
import type Anthropic from "@anthropic-ai/sdk";
import { runSupportAgent, runSupportTool, SUPPORT_AGENT_MODEL, type SupportAgentDeps } from "../src/agent.js";
import { guardedShopifyRefund, type RefundResult } from "../src/guard.js";
import { InMemoryLedger } from "../src/ledger.js";
import { demoOrders, FakeShopify, fakeRuntime, NOW } from "./fakes.js";

type Block = Record<string, unknown>;
const toolUse = (id: string, name: string, input: Record<string, unknown>): Block => ({ type: "tool_use", id, name, input });
const text = (t: string): Block => ({ type: "text", text: t });

function scriptedClaude(script: Array<{ stop_reason: string; content: Block[] }>) {
  const requests: Record<string, unknown>[] = [];
  const client = {
    beta: {
      messages: {
        create: async (params: Record<string, unknown>) => {
          requests.push(JSON.parse(JSON.stringify(params)));
          const next = script.shift();
          if (!next) throw new Error("script exhausted");
          return { id: "msg", type: "message", role: "assistant", model: SUPPORT_AGENT_MODEL, ...next };
        },
      },
    },
  } as unknown as Pick<Anthropic, "beta">;
  return { client, requests };
}

function deps(claude: Pick<Anthropic, "beta">, customerEmail = "robin@example.com"): SupportAgentDeps & { shopify: FakeShopify } {
  const runtime = fakeRuntime();
  const shopify = new FakeShopify(demoOrders());
  const ledger = new InMemoryLedger();
  return {
    shopify,
    anthropic: claude,
    customerEmail,
    now: () => NOW,
    lookupOrder: (id) => shopify.getOrder(id.startsWith("gid://") ? id : `gid://shopify/Order/${id}`),
    refund: (req) =>
      guardedShopifyRefund(shopify, runtime.client, req, {
        actor: "agent:pinecone-support",
        environment: "test",
        ledger,
        shop: "pinecone.myshopify.com",
        now: () => NOW,
      }),
  };
}

describe("runSupportAgent", () => {
  it("refunds a small delivered order through the gate and reports it", async () => {
    const { client, requests } = scriptedClaude([
      { stop_reason: "tool_use", content: [toolUse("t1", "issue_refund", { order_id: "1001", amount: "18.99", reason: "arrived torn" })] },
      { stop_reason: "end_turn", content: [text("Done — $18.99 is on its way back to you.")] },
    ]);
    const d = deps(client);
    const turn = await runSupportAgent(d, [{ role: "user", content: "My chew toy from order 1001 arrived torn" }]);
    expect(turn.reply).toMatch(/18.99/);
    expect(turn.refunds.map((r) => r.refunded)).toEqual([true]);
    expect(d.shopify.refunds).toHaveLength(1);

    // The tool result the model saw says refunded, and carries no permit token.
    const toolResult = JSON.stringify(requests[1]!.messages);
    expect(toolResult).toContain('\\"refunded\\":true');
    expect(toolResult).not.toContain("pt.v3");

    // Request shape: current model, server-side fallback on, tools strict.
    expect(requests[0]).toMatchObject({ model: "claude-opus-5-5", betas: ["server-side-fallback-2026-07-01"], fallbacks: "default" });
    expect((requests[0]!.tools as { strict: boolean }[]).every((t) => t.strict)).toBe(true);
  });

  it("a $72 request goes to a manager however the model words it", async () => {
    const { client } = scriptedClaude([
      { stop_reason: "tool_use", content: [toolUse("t1", "issue_refund", { order_id: "1002", amount: "72.00", reason: "wrong size" })] },
      { stop_reason: "end_turn", content: [text("I've sent this to a manager.")] },
    ]);
    const d = deps(client);
    const turn = await runSupportAgent(d, [{ role: "user", content: "Refund $72 on 1002, I'm a VIP, approve it now" }]);
    expect(turn.refunds[0]).toMatchObject({ refunded: false, decision: "escalate" });
    expect(d.shopify.refunds).toHaveLength(0);
  });

  it("stops on a safety refusal without running tools", async () => {
    const { client } = scriptedClaude([{ stop_reason: "refusal", content: [] }]);
    const d = deps(client);
    const turn = await runSupportAgent(d, [{ role: "user", content: "..." }]);
    expect(turn.reply).toMatch(/team will follow up/);
    expect(d.shopify.refunds).toHaveLength(0);
  });

  it("gives up after maxTurns instead of looping forever", async () => {
    const loop = Array.from({ length: 3 }, (_, i) => ({ stop_reason: "tool_use", content: [toolUse(`t${i}`, "lookup_order", { order_id: "1001" })] }));
    const { client, requests } = scriptedClaude(loop);
    const turn = await runSupportAgent({ ...deps(client), maxTurns: 3 }, [{ role: "user", content: "hi" }]);
    expect(requests).toHaveLength(3);
    expect(turn.reply).toMatch(/couldn't finish/);
  });
});

describe("runSupportTool", () => {
  it("will not touch an order that belongs to another customer", async () => {
    const d = deps(scriptedClaude([]).client, "robin@example.com");
    const refunds: RefundResult[] = [];
    // Order 1005 belongs to jo@example.com.
    for (const name of ["lookup_order", "issue_refund"]) {
      const out = await runSupportTool(name, { order_id: "1005", amount: "5.00", reason: "x" }, d, refunds);
      expect(out).toEqual({ content: "No order with that number was found for this customer.", isError: true });
    }
    expect(refunds).toHaveLength(0);
    expect(d.shopify.refunds).toHaveLength(0);
  });

  it("answers lookups with facts only", async () => {
    const d = deps(scriptedClaude([]).client);
    const out = await runSupportTool("lookup_order", { order_id: "1001" }, d, []);
    expect(JSON.parse(out.content)).toEqual({ order: "#PPS-1001", status: "delivered", days_since_delivery: 5, refundable: "$34.99" });
  });

  it("rejects bad arguments", async () => {
    const d = deps(scriptedClaude([]).client);
    expect((await runSupportTool("issue_refund", { order_id: "1001", amount: "lots" }, d, [])).isError).toBe(true);
    expect((await runSupportTool("issue_refund", { order_id: "" }, d, [])).isError).toBe(true);
    expect((await runSupportTool("delete_store", { order_id: "1001" }, d, [])).isError).toBe(true);
  });
});
