import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { alarmRecord, appendEvidence } from "../src/evidence-log.js";
import { guardedShopifyRefund } from "../src/guard.js";
import { InMemoryLedger } from "../src/ledger.js";
import { demoOrders, FakeShopify, fakeRuntime, NOW } from "./fakes.js";

const payload = (currency?: string) => ({
  id: 91,
  order_id: 1001,
  note: "x",
  transactions: [{ kind: "refund", status: "success", amount: "18.99", ...(currency ? { currency } : {}) }],
});

describe("alarmRecord", () => {
  it("records a verdict with the order gid, and the currency only when the payload states one", () => {
    expect(alarmRecord({ verdict: "authorized", refundId: "91", orderId: "1001", amountCents: 1899, gateRef: "g-1" }, payload("usd"), NOW)).toEqual({
      schema: "atlasent.refund_alarm.v1",
      at: NOW.toISOString(),
      system: "shopify",
      refund_id: "91",
      target: "gid://shopify/Order/1001",
      amount_cents: 1899,
      currency: "USD",
      verdict: "authorized",
      reason: null,
      gate_ref: "g-1",
    });
    const u = alarmRecord({ verdict: "unauthorized", refundId: "92", orderId: "1002", amountCents: null, reason: "no gate reference" }, payload(), NOW);
    expect(u).toMatchObject({ verdict: "unauthorized", reason: "no gate reference", gate_ref: null, amount_cents: null, currency: null });
  });

  it("does not guess a currency when the transactions disagree", () => {
    const mixed = { id: 1, order_id: 2, transactions: [{ kind: "refund", amount: "1.00", currency: "USD" }, { kind: "refund", amount: "1.00", currency: "CAD" }] };
    expect(alarmRecord({ verdict: "unauthorized", refundId: "1", orderId: "2", amountCents: 200, reason: "r" }, mixed, NOW).currency).toBeNull();
  });
});

describe("appendEvidence", () => {
  it("appends one JSON line per decision, never the permit token", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "evidence-")), "log.jsonl");
    const runtime = fakeRuntime();
    const shopify = new FakeShopify(demoOrders());
    const options = {
      actor: "shopify-cli:t",
      environment: "test",
      ledger: new InMemoryLedger(),
      shop: "pinecone-pet-supply.myshopify.com",
      now: () => NOW,
      onDecision: (r: Parameters<typeof appendEvidence>[1]) => appendEvidence(path, r),
    };
    await guardedShopifyRefund(shopify, runtime.client, { orderId: "1001", amountCents: 1899 }, options);
    await guardedShopifyRefund(shopify, runtime.client, { orderId: "1002", amountCents: 7200 }, options);
    const text = readFileSync(path, "utf8");
    expect(text.trim().split("\n").map((l) => JSON.parse(l).outcome)).toEqual(["refunded", "escalated"]);
    expect(text).not.toContain("pt.v3");
  });
});
