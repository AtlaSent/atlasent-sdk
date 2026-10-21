import { createHmac } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { InMemoryLedger, refundNote } from "../src/ledger.js";
import { createGateHandler } from "../src/server.js";
import { signSessionToken } from "../src/session-token.js";
import type { RefundAuditVerdict, RefundWebhookPayload } from "../src/webhook.js";
import { demoOrders, FakeShopify, fakeRuntime, NOW } from "./fakes.js";

const CLIENT_ID = "client-123";
const SECRET = "shpss_secret";
const SHOP = "pinecone.myshopify.com";
const t = Math.floor(NOW.getTime() / 1000);

let server: Server | undefined;
afterEach(() => new Promise<void>((r) => (server ? server.close(() => r()) : r())));

async function start(extra: { onVerdict?: (v: RefundAuditVerdict, p: RefundWebhookPayload, shop: string) => void } = {}) {
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
  fetch(`${base}/api/refunds`, { method: "POST", headers: { authorization: auth, "content-type": "application/json" }, body: JSON.stringify(body) });

describe("POST /api/refunds (the admin button)", () => {
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
