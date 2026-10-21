import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { InMemoryLedger, refundNote, type LedgerEntry } from "../src/ledger.js";
import { auditRefundWebhook, verifyShopifyWebhookHmac } from "../src/webhook.js";

const SECRET = "shpss_test_secret";

describe("verifyShopifyWebhookHmac", () => {
  const body = JSON.stringify({ id: 1 });
  const good = createHmac("sha256", SECRET).update(body).digest("base64");
  it("accepts the right signature", () => expect(verifyShopifyWebhookHmac(body, good, SECRET)).toBe(true));
  it("rejects a tampered body", () => expect(verifyShopifyWebhookHmac(body + " ", good, SECRET)).toBe(false));
  it("rejects a wrong secret", () => expect(verifyShopifyWebhookHmac(body, good, "other")).toBe(false));
  it("rejects a missing header", () => expect(verifyShopifyWebhookHmac(body, undefined, SECRET)).toBe(false));
  it("rejects an empty secret", () => expect(verifyShopifyWebhookHmac(body, createHmac("sha256", "").update(body).digest("base64"), "")).toBe(false));
});

const entry = (over: Partial<LedgerEntry> = {}): LedgerEntry => ({
  gate_ref: "ref-1",
  permit_sha256: "x",
  audit_hash: "a",
  order_id: "gid://shopify/Order/1001",
  amount_cents: 1899,
  actor_id: "shopify-staff:s/1",
  authorized_at: "2026-10-20T12:00:00Z",
  ...over,
});

const payload = (over: Record<string, unknown> = {}) => ({
  id: 555,
  order_id: 1001,
  note: refundNote("ref-1", "arrived torn"),
  transactions: [{ kind: "refund", status: "success", amount: "18.99" }],
  ...over,
});

describe("auditRefundWebhook", () => {
  it("accounts for a gated refund, even before the guard recorded its refund id", async () => {
    const ledger = new InMemoryLedger();
    await ledger.recordAuthorized(entry());
    expect(await auditRefundWebhook(payload(), ledger)).toMatchObject({ verdict: "authorized", gateRef: "ref-1", amountCents: 1899 });
  });

  it("the same delivery twice is still authorized (Shopify retries)", async () => {
    const ledger = new InMemoryLedger();
    await ledger.recordAuthorized(entry());
    await auditRefundWebhook(payload(), ledger);
    expect((await auditRefundWebhook(payload(), ledger)).verdict).toBe("authorized");
  });

  const flagged: Array<[string, Record<string, unknown>, LedgerEntry | null, RegExp]> = [
    ["a staff refund in the admin with no note", { note: "" }, entry(), /no AtlaSent gate reference/],
    ["a note naming an unknown reference", { note: refundNote("made-up") }, entry(), /not in the permit ledger/],
    ["a copied note on another order", { order_id: 2002 }, entry(), /different order/],
    ["a copied note with a bigger amount", { transactions: [{ kind: "refund", status: "success", amount: "180.00" }] }, entry(), /1899 cents/],
    ["a copied note on a second refund", { id: 777 }, entry({ refund_id: "gid://shopify/Refund/555" }), /different refund/],
  ];
  for (const [name, over, e, why] of flagged) {
    it(`flags ${name}`, async () => {
      const ledger = new InMemoryLedger();
      if (e) await ledger.recordAuthorized(e);
      const v = await auditRefundWebhook(payload(over), ledger);
      expect(v.verdict).toBe("unauthorized");
      expect(v.verdict === "unauthorized" && v.reason).toMatch(why);
    });
  }

  it("flags a second refund reusing a reference the first one already claimed", async () => {
    const ledger = new InMemoryLedger();
    await ledger.recordAuthorized(entry());
    await auditRefundWebhook(payload(), ledger);
    const v = await auditRefundWebhook(payload({ id: 999 }), ledger);
    expect(v).toMatchObject({ verdict: "unauthorized", reason: expect.stringMatching(/already accounts/) });
  });

  it("a PENDING refund transaction (asynchronous gateway) still matches", async () => {
    const ledger = new InMemoryLedger();
    await ledger.recordAuthorized(entry());
    const v = await auditRefundWebhook(payload({ transactions: [{ kind: "refund", status: "pending", amount: "18.99" }] }), ledger);
    expect(v.verdict).toBe("authorized");
  });

  it("a FAILED refund transaction does not count toward the amount", async () => {
    const ledger = new InMemoryLedger();
    await ledger.recordAuthorized(entry());
    const v = await auditRefundWebhook(payload({ transactions: [{ kind: "refund", status: "failure", amount: "18.99" }] }), ledger);
    expect(v.verdict).toBe("unauthorized");
  });

  it("an entry the gate cancelled vouches for nothing", async () => {
    const ledger = new InMemoryLedger();
    await ledger.recordAuthorized(entry());
    await ledger.recordAborted("ref-1", "order_changed");
    expect(await auditRefundWebhook(payload(), ledger)).toMatchObject({ verdict: "unauthorized", reason: expect.stringMatching(/stopped/) });
  });
});
