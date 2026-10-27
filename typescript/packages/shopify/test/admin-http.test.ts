/** Real Admin client + real guard over scripted HTTP; no native store calls. */
import { describe, expect, it } from "vitest";
import { createAdminClient, DEFAULT_ADMIN_API_VERSION, type RefundCreateInput, type RefundSubmissionOptions } from "../src/admin.js";
import { guardedShopifyRefund } from "../src/guard.js";
import { InMemoryLedger } from "../src/ledger.js";
import { reconcileShopifyRefund } from "../src/reconcile.js";
import { fakeRuntime, makeOrder, NOW } from "./fakes.js";

const SHOP = "pinecone.myshopify.com";
const KEY = "11111111-2222-4333-8444-555555555555";
const INPUT: RefundCreateInput = {
  orderId: "gid://shopify/Order/1001", note: `AtlaSent gate ref ${KEY}`, notify: false,
  transactions: [{ orderId: "gid://shopify/Order/1001", parentId: "gid://shopify/OrderTransaction/10011", kind: "REFUND", gateway: "manual", amount: "18.99" }],
};

function nativeHttp(options: { readVersion?: string | null; mutationVersion?: string | null; mutationThrows?: boolean; httpStatus?: number } = {}) {
  const calls: { url: string; init: RequestInit; body: { query: string; variables: Record<string, unknown> } }[] = [];
  let writes = 0;
  let saved: RefundCreateInput | undefined;
  const order = makeOrder({ id: 1001, delivery: "delivered", paid: "34.99" });
  const response = (data: unknown, version: string | null) => Response.json({ data }, {
    status: options.httpStatus ?? 200,
    headers: version === null ? {} : { "x-shopify-api-version": version },
  });
  const fetchImpl = (async (url, init) => {
    const body = JSON.parse(String(init?.body)) as (typeof calls)[number]["body"];
    calls.push({ url: String(url), init: init!, body });
    if (body.query.includes("refundCreate(")) {
      writes++;
      saved = structuredClone(body.variables.input) as RefundCreateInput;
      if (options.mutationThrows) throw new Error("response lost after commit");
      return response({ refundCreate: {
        refund: { id: "gid://shopify/Refund/91", createdAt: NOW.toISOString(), totalRefundedSet: { shopMoney: { amount: "18.99", currencyCode: "USD" } } },
        userErrors: [],
      } }, options.mutationVersion === undefined ? DEFAULT_ADMIN_API_VERSION : options.mutationVersion);
    }
    if (body.query.includes("AtlaSentRefundReadback")) {
      return response({ node: saved ? {
        id: "gid://shopify/Refund/91", createdAt: NOW.toISOString(), note: saved.note, order: { id: saved.orderId },
        totalRefundedSet: { shopMoney: { amount: "18.99", currencyCode: "USD" } },
        transactions: { pageInfo: { hasNextPage: false }, nodes: [{
          id: "gid://shopify/OrderTransaction/991", kind: "REFUND", status: "SUCCESS", gateway: "manual",
          amountSet: { shopMoney: { amount: "18.99", currencyCode: "USD" } }, parentTransaction: { id: "gid://shopify/OrderTransaction/10011" },
        }] },
      } : null }, DEFAULT_ADMIN_API_VERSION);
    }
    return response({ order: structuredClone(order) }, options.readVersion === undefined ? DEFAULT_ADMIN_API_VERSION : options.readVersion);
  }) as typeof fetch;
  const admin = createAdminClient({ shop: SHOP, accessToken: "test-shopify-token", fetch: fetchImpl });
  return { admin, calls, writes: () => writes, fetchImpl };
}

describe("reviewed Shopify API version", () => {
  it("pins native reads to the reviewed endpoint and refuses redirects", async () => {
    const h = nativeHttp();
    await h.admin.getOrder("1001");
    expect(h.calls[0]!.url).toBe(`https://${SHOP}/admin/api/2026-07/graphql.json`);
    expect(new Headers(h.calls[0]!.init.headers).get("x-shopify-access-token")).toBe("test-shopify-token");
    expect(h.calls[0]!.init.redirect).toBe("error");
  });
  for (const version of ["2025-10", "2026-10", "unstable", "2026-07/../../bad", ""]) {
    it(`refuses unreviewed configured version ${JSON.stringify(version)} before HTTP`, () => {
      const h = nativeHttp();
      expect(() => createAdminClient({ shop: SHOP, accessToken: "test-token", apiVersion: version, fetch: h.fetchImpl })).toThrow(/reviewed API version/);
      expect(h.calls).toHaveLength(0);
    });
  }
  for (const version of [null, "2026-01", "2026-10"]) {
    it(`stops a guard on served version ${version ?? "missing"} before authorization or native write`, async () => {
      const h = nativeHttp({ readVersion: version });
      const runtime = fakeRuntime();
      const result = await guardedShopifyRefund(h.admin, runtime.client, { orderId: "1001", amountCents: 1899 }, {
        shop: SHOP, environment: "test", actor: "shopify-staff:test/1", ledger: new InMemoryLedger(), now: () => NOW,
      });
      expect(result).toMatchObject({ refunded: false, decision: "error", reason: expect.stringMatching(/version mismatch/) });
      expect(runtime.evaluateBodies).toHaveLength(0);
      expect(h.writes()).toBe(0);
    });
  }
  it("retains an authentication/HTTP failure instead of treating its missing version as success", async () => {
    const h = nativeHttp({ httpStatus: 401, readVersion: null });
    await expect(h.admin.getOrder("1001")).rejects.toThrow(/HTTP 401/);
  });
});

describe("native refund idempotency contract", () => {
  it("sends the key as a GraphQL directive variable without changing the refund input", async () => {
    const h = nativeHttp();
    expect((await h.admin.createRefund(INPUT, { idempotencyKey: KEY })).id).toBe("gid://shopify/Refund/91");
    const sent = h.calls[0]!.body;
    expect(sent.query).toContain("$idempotencyKey: String!");
    expect(sent.query).toContain("@idempotent(key: $idempotencyKey)");
    expect(sent.variables).toEqual({ input: INPUT, idempotencyKey: KEY });
    expect(h.writes()).toBe(1);
  });
  for (const submission of [undefined, { idempotencyKey: "" }, { idempotencyKey: "new-key" }, { idempotencyKey: "\"}) { shop { id } }" }]) {
    it(`refuses a missing/malformed execution key ${JSON.stringify(submission)} without HTTP`, async () => {
      const h = nativeHttp();
      await expect(h.admin.createRefund(INPUT, submission)).rejects.toThrow(/no request was sent/);
      expect(h.calls).toHaveLength(0);
    });
  }
  it("the guard forwards its saved execution reference through send and native confirmation", async () => {
    const h = nativeHttp();
    const runtime = fakeRuntime();
    const ledger = new InMemoryLedger();
    const result = await guardedShopifyRefund(h.admin, runtime.client, { orderId: "1001", amountCents: 1899, businessRequestId: "support-case-1" }, {
      shop: SHOP, environment: "test", actor: "shopify-staff:test/1", ledger, now: () => NOW,
    });
    expect(result.refunded).toBe(true);
    const mutation = h.calls.find(c => c.body.query.includes("refundCreate("))!;
    expect(mutation.body.variables.idempotencyKey).toBe(result.gateRef);
    expect((await ledger.get(result.gateRef))?.refund_id).toBe("gid://shopify/Refund/91");
    expect(h.calls.filter(c => c.body.query.includes("AtlaSentRefundReadback"))).toHaveLength(1);
    expect(h.writes()).toBe(1);
  });
  for (const failure of ["lost_response", "served_version_changed", "served_version_missing"] as const) {
    it(`${failure} after submission stays unconfirmed and never triggers another native send`, async () => {
      const h = nativeHttp(failure === "lost_response" ? { mutationThrows: true } : { mutationVersion: failure === "served_version_changed" ? "2026-10" : null });
      const runtime = fakeRuntime();
      const ledger = new InMemoryLedger();
      const options = { shop: SHOP, environment: "test", actor: "shopify-staff:test/1", ledger, now: () => NOW };
      const first = await guardedShopifyRefund(h.admin, runtime.client, { orderId: "1001", amountCents: 1899, businessRequestId: "case-1" }, options);
      expect(first).toMatchObject({ refunded: false, decision: "unconfirmed" });
      expect(await guardedShopifyRefund(h.admin, runtime.client, { orderId: "1001", amountCents: 1899, businessRequestId: "new-case" }, options))
        .toMatchObject({ decision: "reconciliation_required", gateRef: first.gateRef });
      expect(h.writes()).toBe(1);
      expect(await reconcileShopifyRefund(h.admin, ledger, { gateRef: first.gateRef, shop: SHOP, environment: "test", candidateRefundId: "gid://shopify/Refund/91" }))
        .toMatchObject({ status: "succeeded" });
      expect(h.writes()).toBe(1);
    });
  }
  it("an injected provider receives the same saved key; the guard never generates a transport retry key", async () => {
    const h = nativeHttp();
    const runtime = fakeRuntime();
    const keys: string[] = [];
    const original = h.admin.createRefund.bind(h.admin);
    h.admin.createRefund = async (input: RefundCreateInput, submission?: RefundSubmissionOptions) => {
      keys.push(submission!.idempotencyKey);
      return original(input, submission);
    };
    const r = await guardedShopifyRefund(h.admin, runtime.client, { orderId: "1001", amountCents: 1899 }, {
      shop: SHOP, environment: "test", actor: "shopify-staff:test/1", ledger: new InMemoryLedger(), now: () => NOW,
    });
    expect(keys).toEqual([r.gateRef]);
  });
});
