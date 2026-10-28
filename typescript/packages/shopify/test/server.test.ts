import { createHmac } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { InMemoryLedger, refundNote } from "../src/ledger.js";
import { createGateHandler } from "../src/server.js";
import type { ShopifyAdmin } from "../src/admin.js";
import { signSessionToken } from "../src/session-token.js";
import type { RefundAuditVerdict, RefundWebhookPayload } from "../src/webhook.js";
import type { RefundDecisionRecord } from "../src/decision-record.js";
import { CUSTOMER_REFUND_ISSUE, FINANCE_PAYMENT_AUTHORIZE, type RefundActionType } from "../src/guard.js";
import { demoOrders, FakeShopify, fakeRuntime, makeOrder, NOW } from "./fakes.js";

const CLIENT_ID = "client-123";
const SECRET = "shpss_secret";
const SHOP = "pinecone.myshopify.com";
const t = Math.floor(NOW.getTime() / 1000);

let server: Server | undefined;
afterEach(() => new Promise<void>((r) => (server ? server.close(() => r()) : r())));

async function start(
  extra: {
    actionType?: RefundActionType;
    onVerdict?: (v: RefundAuditVerdict, p: RefundWebhookPayload, shop: string) => void;
    onDecision?: (r: RefundDecisionRecord) => void;
    adminFor?: (shop: string, token: string) => Promise<ShopifyAdmin>;
  } = {},
) {
  const runtime = fakeRuntime();
  const shopify = new FakeShopify(demoOrders());
  const ledger = new InMemoryLedger();
  const alerts: RefundAuditVerdict[] = [];
  const shopsAsked: string[] = [];
  server = createServer(
    createGateHandler({
      clientId: CLIENT_ID,
      clientSecret: SECRET,
      environment: "test",
      ledger,
      atlasent: runtime.client,
      adminFor: async (shop) => {
        shopsAsked.push(shop);
        return shopify;
      },
      allowedShops: [SHOP],
      onUnauthorizedRefund: (v) => void alerts.push(v),
      ...extra,
      now: () => NOW,
    }),
  );
  await new Promise<void>((r) => server!.listen(0, "127.0.0.1", () => r()));
  const base = `http://127.0.0.1:${(server!.address() as AddressInfo).port}`;
  return { base, runtime, shopify, ledger, alerts, shopsAsked };
}

const token = (over: Record<string, unknown> = {}) =>
  signSessionToken(
    { iss: `https://${SHOP}/admin`, dest: `https://${SHOP}`, aud: CLIENT_ID, sub: "42", exp: t + 60, nbf: t - 5, ...over },
    SECRET,
  );

const postRefund = (base: string, body: unknown, auth = `Bearer ${token()}`) =>
  fetch(`${base}/api/refunds`, { method: "POST", headers: { authorization: auth, "content-type": "application/json" }, body: JSON.stringify(body && typeof body === "object" ? { businessRequestId: "test-case", ...body } : body) });

describe("POST /api/refunds (the admin button)", () => {
  it("uses only the host-configured canonical action, ignoring a caller action override", async () => {
    const s = await start({ actionType: CUSTOMER_REFUND_ISSUE });
    const response = await postRefund(s.base, { orderId: "1001", amount: "18.99", actionType: FINANCE_PAYMENT_AUTHORIZE });
    expect(response.status).toBe(200);
    expect((await response.json()).refunded).toBe(true);
    expect(s.runtime.evaluateBodies[0]).toMatchObject({ action_type: CUSTOMER_REFUND_ISSUE });
    expect(s.runtime.verifyBodies[0]).toMatchObject({ action_type: CUSTOMER_REFUND_ISSUE });
  });

  it("a caller cannot opt the legacy host into the canonical action", async () => {
    const s = await start();
    await postRefund(s.base, { orderId: "1001", amount: "18.99", actionType: CUSTOMER_REFUND_ISSUE });
    expect(s.runtime.evaluateBodies[0]).toMatchObject({ action_type: FINANCE_PAYMENT_AUTHORIZE });
  });

  it("requires a stable request ID and replays cannot cause another refund", async () => {
    const s = await start();
    expect((await postRefund(s.base, { orderId: "1001", amount: "18.99", businessRequestId: "" })).status).toBe(400);
    expect(s.runtime.evaluateBodies).toHaveLength(0);
    const first = await (await postRefund(s.base, { orderId: "1001", amount: "18.99" })).json();
    const retry = await (await postRefund(s.base, { orderId: "1001", amount: "18.99" })).json();
    expect(retry).toMatchObject({ decision: "duplicate_request", gateRef: first.gateRef });
    const recovered = await fetch(`${s.base}/api/refunds/reconcile`, { method: "POST", headers: { authorization: `Bearer ${token()}`, "content-type": "application/json" }, body: JSON.stringify({ gateRef: retry.gateRef }) });
    expect(await recovered.json()).toMatchObject({ status: "succeeded" });
    expect(s.shopify.refunds).toHaveLength(1);
  });

  it("authenticates reconciliation and reads the original outcome without a second send", async () => {
    const s = await start();
    s.shopify.failRefundRead = true;
    const first = await (await postRefund(s.base, { orderId: "1001", amount: "18.99" })).json();
    expect(first.decision).toBe("unconfirmed");
    s.shopify.failRefundRead = false;
    const reconcile = (auth: string, gateRef: string) => fetch(`${s.base}/api/refunds/reconcile`, {
      method: "POST", headers: { authorization: auth, "content-type": "application/json" }, body: JSON.stringify({ gateRef }),
    });
    expect((await reconcile("", first.gateRef)).status).toBe(401);
    expect(await (await reconcile(`Bearer ${token()}`, "unknown")).json()).toMatchObject({ status: "refused" });
    expect(await (await reconcile(`Bearer ${token()}`, first.gateRef)).json()).toMatchObject({ status: "succeeded" });
    expect(s.shopify.refunds).toHaveLength(1);
  });
  it("refunds through the gate and names the staff member as the actor", async () => {
    const s = await start();
    const res = await postRefund(s.base, { orderId: "gid://shopify/Order/1001", amount: "18.99", reason: "torn" });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toMatchObject({ refunded: true, message: "Refunded $18.99" });
    expect(s.runtime.evaluateBodies[0]).toMatchObject({ actor_id: `shopify-staff:${SHOP}/42` });
    expect(s.shopify.refunds).toHaveLength(1);
    expect(JSON.stringify(body)).not.toContain("pt.v3");
  });

  it("shows the manager-review outcome for $72", async () => {
    const s = await start();
    const body = await (await postRefund(s.base, { orderId: "gid://shopify/Order/1002", amount: "72.00" })).json();
    expect(body).toMatchObject({ refunded: false, decision: "escalate", denyCode: "MANAGER_APPROVAL_REQUIRED", message: expect.stringMatching(/manager/) });
    expect(s.shopify.refunds).toHaveLength(0);
  });

  it("rejects requests without a valid session token", async () => {
    const s = await start();
    for (const auth of ["", "Bearer nope", `Bearer ${signSessionToken({ iss: `https://${SHOP}/admin`, dest: `https://${SHOP}`, aud: CLIENT_ID, exp: t + 60, nbf: t - 5 }, "wrong")}`]) {
      expect((await postRefund(s.base, { orderId: "1001", amount: "1.00" }, auth)).status).toBe(401);
    }
    expect(s.runtime.evaluateBodies).toHaveLength(0);
  });

  it("rejects a valid token from a shop that is not allowed", async () => {
    const s = await start();
    const other = token({ iss: "https://other.myshopify.com/admin", dest: "https://other.myshopify.com" });
    expect((await postRefund(s.base, { orderId: "1001", amount: "1.00" }, `Bearer ${other}`)).status).toBe(403);
    expect(s.shopsAsked).toHaveLength(0);
  });

  it("rejects malformed bodies", async () => {
    const s = await start();
    for (const body of [{}, { orderId: "1001" }, { orderId: "1001", amount: 18.99 }, { orderId: "1001", amount: "18.999" }]) {
      expect((await postRefund(s.base, body)).status).toBe(400);
    }
    expect(s.runtime.evaluateBodies).toHaveLength(0);
  });

  it("answers the CORS preflight", async () => {
    const s = await start();
    const res = await fetch(`${s.base}/api/refunds`, { method: "OPTIONS" });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-headers")).toMatch(/authorization/);
  });
});

describe("evidence log failures", () => {
  it("a decision the log could not take still refunds, and the server says the log lost it", async () => {
    const errors: string[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((m: unknown) => void errors.push(String(m)));
    try {
      const s = await start({
        onDecision: () => {
          throw new Error("disk full");
        },
      });
      const body = await (await postRefund(s.base, { orderId: "gid://shopify/Order/1001", amount: "18.99" })).json();
      expect(body.refunded).toBe(true);
      expect(errors.map((e) => JSON.parse(e))).toEqual([expect.objectContaining({ warning: "decision_not_logged", gateRef: body.gateRef })]);
    } finally {
      spy.mockRestore();
    }
  });
});

describe("POST /webhooks/refunds-create (the alarm)", () => {
  const deliver = (base: string, payload: unknown, opts: { secret?: string; topic?: string; shop?: string } = {}) => {
    const raw = JSON.stringify(payload);
    return fetch(`${base}/webhooks/refunds-create`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-shopify-hmac-sha256": createHmac("sha256", opts.secret ?? SECRET).update(raw).digest("base64"),
        "x-shopify-topic": opts.topic ?? "refunds/create",
        "x-shopify-shop-domain": opts.shop ?? SHOP,
      },
      body: raw,
    });
  };

  it("stays quiet for a refund the gate issued", async () => {
    const s = await start();
    const r = await (await postRefund(s.base, { orderId: "gid://shopify/Order/1001", amount: "18.99" })).json();
    const res = await deliver(s.base, {
      id: 91,
      order_id: 1001,
      note: refundNote(r.gateRef),
      transactions: [{ kind: "refund", status: "success", amount: "18.99" }],
    });
    expect(await res.json()).toEqual({ verdict: "authorized" });
    expect(s.alerts).toHaveLength(0);
  });

  it("hands every verdict to onVerdict, and a failing one does not change the response", async () => {
    const seen: string[] = [];
    const s = await start({
      onVerdict: (v, p, shop) => {
        seen.push(`${v.verdict}:${p.id}:${shop}`);
        throw new Error("disk full");
      },
    });
    const res = await deliver(s.base, { id: 93, order_id: 1002, note: "around the gate", transactions: [{ kind: "refund", status: "success", amount: "129.00" }] });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ verdict: "unauthorized" });
    expect(seen).toEqual([`unauthorized:93:${SHOP}`]);
  });

  it("alerts on a refund made in the Shopify admin around the gate", async () => {
    const s = await start();
    const res = await deliver(s.base, { id: 92, order_id: 1002, note: "customer asked nicely", transactions: [{ kind: "refund", status: "success", amount: "129.00" }] });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ verdict: "unauthorized" });
    expect(s.alerts).toEqual([expect.objectContaining({ verdict: "unauthorized", orderId: "1002", amountCents: 12900 })]);
  });

  it("rejects a delivery with a bad signature and does not alert", async () => {
    const s = await start();
    expect((await deliver(s.base, { id: 1, order_id: 1 }, { secret: "forged" })).status).toBe(401);
    expect(s.alerts).toHaveLength(0);
  });

  it("ignores other topics and other shops", async () => {
    const s = await start();
    expect(await (await deliver(s.base, { id: 1, order_id: 1 }, { topic: "orders/create" })).json()).toEqual({ ignored: true });
    expect(await (await deliver(s.base, { id: 1, order_id: 1 }, { shop: "other.myshopify.com" })).json()).toEqual({ ignored: true });
    expect(s.alerts).toHaveLength(0);
  });
});

const postPreview = (base: string, body: unknown, auth = `Bearer ${token()}`) =>
  fetch(`${base}/api/operations/refund-preview`, {
    method: "POST", headers: { authorization: auth, "content-type": "application/json" },
    body: JSON.stringify(body),
  });

describe("POST /api/operations/refund-preview (read-only first value)", () => {
  it("returns a useful next step without runtime evaluation, refund or customer message", async () => {
    const s = await start();
    const res = await postPreview(s.base, { orderId: "1001", amount: "18.99", approved: true, customerEmail: "forged@example.com" });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toMatchObject({
      schema: "atlasent.shopify_refund_operations_preview.v1",
      mode: "read_only", authorization: "not_evaluated", execution: "not_attempted",
      customer_notification: "not_sent", disposition: "routine_candidate",
      next_step: "verify_business_eligibility",
    });
    expect(body.missing_proofs).toContain("independent_authority_and_approval");
    expect(JSON.stringify(body)).not.toContain("forged@example.com");
    expect(s.runtime.evaluateBodies).toHaveLength(0);
    expect(s.runtime.verifyBodies).toHaveLength(0);
    expect(s.shopify.refunds).toHaveLength(0);
    expect(s.shopify.emailReads).toBe(0);
  });

  it("refuses missing/invalid sessions, other shops, and malformed input before any read", async () => {
    const s = await start();
    expect((await postPreview(s.base, { orderId: "1001", amount: "1.00" }, "")).status).toBe(401);
    const other = token({ iss: "https://other.myshopify.com/admin", dest: "https://other.myshopify.com" });
    expect((await postPreview(s.base, { orderId: "1001", amount: "1.00" }, `Bearer ${other}`)).status).toBe(403);
    for (const body of [
      {}, { orderId: "1001" }, { orderId: "1001", amount: "0.00" },
      { orderId: "https://other.myshopify.com/orders/1001", amount: "1.00" },
      { orderId: "1001", amount: 10 },
    ]) {
      expect((await postPreview(s.base, body)).status).toBe(400);
    }
    expect(s.shopsAsked).toHaveLength(0);
    expect(s.shopify.refunds).toHaveLength(0);
  });

  it("rejects an Admin client that returns a different order identity", async () => {
    const s = await start({
      adminFor: async () => ({
        getOrder: async () => makeOrder({ id: 1002, delivery: "delivered" }),
        createRefund: async () => { throw new Error("must never call"); },
      }),
    });
    const res = await postPreview(s.base, { orderId: "1001", amount: "1.00" });
    expect(res.status).toBe(503);
    expect(await res.json()).toMatchObject({ mode: "read_only" });
    expect(s.runtime.evaluateBodies).toHaveLength(0);
  });

  it("returns an explicit unavailable state on a missing order, without fabricating completion", async () => {
    const s = await start();
    const res = await postPreview(s.base, { orderId: "999999", amount: "1.00" });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({
      disposition: "unavailable", next_step: "retry_source_read", execution: "not_attempted",
    });
    expect(s.shopify.refunds).toHaveLength(0);
  });

  it("returns 503 when Shopify access is unavailable; does not guess from the request", async () => {
    const s = await start({ adminFor: async () => { throw new Error("secret provider detail"); } });
    const res = await postPreview(s.base, { orderId: "1001", amount: "1.00" });
    expect(res.status).toBe(503);
    expect(JSON.stringify(await res.json())).not.toContain("secret provider detail");
    expect(s.runtime.evaluateBodies).toHaveLength(0);
  });

  it("answers CORS preflight for the preview route", async () => {
    const s = await start();
    const res = await fetch(`${s.base}/api/operations/refund-preview`, { method: "OPTIONS" });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-methods")).toContain("POST");
  });
});


