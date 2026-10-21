import { createHmac } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { InMemoryLedger, type LedgerEntry } from "../src/ledger.js";
import type { StripeRefund } from "../src/stripe.js";
import { auditStripeRefund, refundFromEvent, verifyStripeSignature, type StripeRefundAuditVerdict } from "../src/webhook.js";
import { createStripeWebhookHandler } from "../src/webhook-server.js";

const SECRET = "whsec_test_secret";
const NOW = new Date("2026-10-20T12:00:00Z");
const T = Math.floor(NOW.getTime() / 1000);
const sign = (body: string, t = T, secret = SECRET) => `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${body}`).digest("hex")}`;

describe("verifyStripeSignature", () => {
  const body = JSON.stringify({ id: "evt_1" });
  const ok = (h: string | undefined, b = body) => verifyStripeSignature(b, h, SECRET, { now: NOW });
  it("accepts a valid signature", () => expect(ok(sign(body))).toBe(true));
  it("accepts when any v1 matches (secret rotation)", () => expect(ok(`${sign(body)},v1=${"0".repeat(64)}`)).toBe(true));
  it("rejects a tampered body", () => expect(ok(sign(body), body + " ")).toBe(false));
  it("rejects a wrong secret", () => expect(ok(sign(body, T, "whsec_other"))).toBe(false));
  it("rejects an old timestamp (replay)", () => expect(ok(sign(body, T - 301))).toBe(false));
  it("rejects a missing or malformed header", () => {
    for (const h of [undefined, "", "t=abc,v1=zz", `v1=${"a".repeat(64)}`, `t=${T}`, "x".repeat(5000)]) expect(ok(h)).toBe(false);
  });
});

const entry = (over: Partial<LedgerEntry> = {}): LedgerEntry => ({
  gate_ref: "ref-1",
  permit_sha256: "x",
  audit_hash: "a",
  payment_intent: "pi_1001",
  amount_cents: 1899,
  actor_id: "support-tool:dana",
  authorized_at: NOW.toISOString(),
  ...over,
});

const refund = (over: Partial<StripeRefund> = {}): StripeRefund => ({
  id: "re_1",
  status: "succeeded",
  amount: 1899,
  currency: "usd",
  charge: "ch_1001",
  payment_intent: "pi_1001",
  metadata: { atlasent_gate_ref: "ref-1" },
  ...over,
});

describe("auditStripeRefund", () => {
  it("accounts for a gated refund, pending or succeeded", async () => {
    for (const status of ["succeeded", "pending", "requires_action"]) {
      const ledger = new InMemoryLedger();
      await ledger.recordAuthorized(entry());
      expect((await auditStripeRefund(refund({ status }), ledger)).verdict).toBe("authorized");
    }
  });

  it("ignores failed and canceled refunds: no money moved", async () => {
    for (const status of ["failed", "canceled"]) {
      expect((await auditStripeRefund(refund({ status, metadata: {} }), new InMemoryLedger())).verdict).toBe("ignored");
    }
  });

  const flagged: Array<[string, Partial<StripeRefund>, LedgerEntry | null, RegExp]> = [
    ["a Dashboard refund with no gate reference", { metadata: {} }, entry(), /no AtlaSent gate reference/],
    ["an unknown reference", { metadata: { atlasent_gate_ref: "made-up" } }, entry(), /not in the permit ledger/],
    ["a copied reference on another payment", { payment_intent: "pi_2002" }, entry(), /different payment/],
    ["a copied reference with a bigger amount", { amount: 18000 }, entry(), /1899 cents/],
    ["a copied reference on a second refund", { id: "re_2" }, entry({ refund_id: "re_1" }), /different refund/],
    ["a reference the gate cancelled", {}, entry({ aborted_reason: "payment_changed" }), /stopped/],
  ];
  for (const [name, over, e, why] of flagged) {
    it(`flags ${name}`, async () => {
      const ledger = new InMemoryLedger();
      if (e) await ledger.recordAuthorized(e);
      const v = await auditStripeRefund(refund(over), ledger);
      expect(v.verdict).toBe("unauthorized");
      expect(v.verdict === "unauthorized" && v.reason).toMatch(why);
    });
  }

  it("one ledger entry accounts for one refund", async () => {
    const ledger = new InMemoryLedger();
    await ledger.recordAuthorized(entry());
    await auditStripeRefund(refund(), ledger);
    expect((await auditStripeRefund(refund(), ledger)).verdict).toBe("authorized"); // Stripe retry
    expect((await auditStripeRefund(refund({ id: "re_9" }), ledger)).verdict).toBe("unauthorized");
  });
});

describe("refundFromEvent", () => {
  it("returns the refund for refund.created only", () => {
    expect(refundFromEvent(JSON.stringify({ type: "refund.created", data: { object: refund() } }))?.id).toBe("re_1");
    expect(refundFromEvent(JSON.stringify({ type: "charge.succeeded", data: { object: {} } }))).toBeNull();
    expect(refundFromEvent(JSON.stringify({ type: "refund.created", data: { object: { id: 1 } } }))).toBeNull();
  });
});

describe("POST /webhooks/stripe", () => {
  let server: Server | undefined;
  afterEach(() => new Promise<void>((r) => (server ? server.close(() => r()) : r())));

  async function start(ledger = new InMemoryLedger()) {
    const alerts: StripeRefundAuditVerdict[] = [];
    server = createServer(createStripeWebhookHandler({ webhookSecret: SECRET, ledger, onUnauthorizedRefund: (v) => void alerts.push(v), now: () => NOW }));
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", () => r()));
    const base = `http://127.0.0.1:${(server!.address() as AddressInfo).port}`;
    const deliver = (event: unknown, sig?: string) => {
      const raw = JSON.stringify(event);
      return fetch(`${base}/webhooks/stripe`, { method: "POST", headers: { "stripe-signature": sig ?? sign(raw) }, body: raw });
    };
    return { deliver, alerts, ledger };
  }

  it("stays quiet for a gated refund and alerts on a Dashboard one", async () => {
    const ledger = new InMemoryLedger();
    await ledger.recordAuthorized(entry());
    const s = await start(ledger);
    expect(await (await s.deliver({ type: "refund.created", data: { object: refund() } })).json()).toEqual({ verdict: "authorized" });
    const res = await s.deliver({ type: "refund.created", data: { object: refund({ id: "re_dash", metadata: {}, amount: 12900, payment_intent: "pi_1002" }) } });
    expect(await res.json()).toEqual({ verdict: "unauthorized" });
    expect(s.alerts).toEqual([expect.objectContaining({ refundId: "re_dash", amountCents: 12900 })]);
  });

  it("rejects a bad signature without alerting", async () => {
    const s = await start();
    const res = await s.deliver({ type: "refund.created", data: { object: refund({ metadata: {} }) } }, sign("other"));
    expect(res.status).toBe(400);
    expect(s.alerts).toHaveLength(0);
  });

  it("hands every verdict to onVerdict, and a failing one does not change the response", async () => {
    const ledger = new InMemoryLedger();
    await ledger.recordAuthorized(entry());
    const seen: string[] = [];
    server = createServer(
      createStripeWebhookHandler({
        webhookSecret: SECRET,
        ledger,
        now: () => NOW,
        onVerdict: (v, r) => {
          seen.push(`${v.verdict}:${r.id}`);
          if (r.id === "re_dash") throw new Error("disk full");
        },
      }),
    );
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", () => r()));
    const base = `http://127.0.0.1:${(server!.address() as AddressInfo).port}`;
    const deliver = (event: unknown) => {
      const raw = JSON.stringify(event);
      return fetch(`${base}/webhooks/stripe`, { method: "POST", headers: { "stripe-signature": sign(raw) }, body: raw });
    };
    await deliver({ type: "refund.created", data: { object: refund() } });
    const res = await deliver({ type: "refund.created", data: { object: refund({ id: "re_dash", metadata: {} }) } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ verdict: "unauthorized" });
    expect(seen).toEqual([`authorized:${refund().id}`, "unauthorized:re_dash"]);
  });

  it("ignores other event types", async () => {
    const s = await start();
    expect(await (await s.deliver({ type: "charge.succeeded", data: { object: {} } })).json()).toEqual({ ignored: true });
  });
});
