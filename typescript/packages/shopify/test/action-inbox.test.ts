import { describe, expect, it } from "vitest";
import { createPreviewObservationPublisher } from "../src/action-inbox.js";
import { previewShopifyRefundOperation } from "../src/operations-preview.js";
import { makeOrder, NOW } from "./fakes.js";

const ORG = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const CONNECTOR = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const SHOP = "preview.myshopify.com";
const ORDER = "gid://shopify/Order/1001";
const preview = () => previewShopifyRefundOperation(makeOrder({ id: 1001, delivery: "delivered" }), 1899, NOW);
const key = () => ({ key_id: "key-1", org_id: ORG, environment: "test", scopes: ["connectors:read", "connectors:write"] });
const connector = () => ({ id: CONNECTOR, org_id: ORG, status: "active", environment: "sandbox", connector_type: "custom", config: { provider: "shopify", shop_domain: SHOP } });

function fixture(extra: { key?: unknown; connector?: unknown; receipt?: (r: Record<string, unknown>) => unknown; status?: number; now?: () => Date; postThrows?: boolean } = {}) {
  const calls: { path: string; init: RequestInit | undefined }[] = [];
  let submitted: Record<string, unknown> | undefined;
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    const path = new URL(String(url)).pathname;
    calls.push({ path, init });
    let value: unknown;
    if (path.endsWith("/v1-api-key-self")) value = extra.key ?? key();
    else if (path.endsWith(`/v1-connectors/${CONNECTOR}`)) value = extra.connector ?? connector();
    else if (path.endsWith(`/v1-connectors/${CONNECTOR}/observations`)) {
      if (extra.postThrows) throw new Error("uncertain transport failure");
      submitted = JSON.parse(String(init?.body)) as Record<string, unknown>;
      const receipt = {
        schema: "atlasent.connector-observation-receipt.v1", event_id: "cccccccc-cccc-cccc-cccc-cccccccccccc",
        observation_id: submitted.event_id, idempotency_key: submitted.idempotency_key,
        organization_id: ORG, connector_id: CONNECTOR, received_at: NOW.toISOString(),
        capability_level: "observe", authority_effect: "none", execution: "not_attempted", verification: "not_performed", duplicate: false,
      };
      value = extra.receipt ? extra.receipt(receipt) : receipt;
    } else throw new Error(`Unexpected endpoint: ${path}`);
    return new Response(JSON.stringify(value), { status: path.endsWith("/observations") ? extra.status ?? 201 : 200 });
  }) as typeof fetch;
  const publish = createPreviewObservationPublisher({
    baseUrl: "https://runtime.example/functions/v1", apiKey: "ask_test_observer", orgId: ORG,
    connectorId: CONNECTOR, environment: "test", fetch: fetchImpl, now: extra.now ?? (() => NOW),
  });
  return { publish, calls, submitted: () => submitted, posts: () => calls.filter(c => c.init?.method === "POST") };
}

describe("explicit Shopify Observe publisher", () => {
  it("binds a fresh preview to the configured org, active connector, actual shop and canonical action", async () => {
    const f = fixture(); const p = preview();
    const receipt = await f.publish({ shop: SHOP, orderId: ORDER, userId: "42", preview: p });
    expect(receipt).toMatchObject({ organization_id: ORG, connector_id: CONNECTOR, authority_effect: "none" });
    expect(f.calls.map(c => c.path)).toEqual([
      "/functions/v1/v1-api-key-self", `/functions/v1/v1-connectors/${CONNECTOR}`, `/functions/v1/v1-connectors/${CONNECTOR}/observations`,
    ]);
    expect(f.submitted()).toMatchObject({
      organization_id: ORG, connector_id: CONNECTOR, source_system: "shopify", capability_level: "observe",
      action: { slug: "customer.refund.issue" }, target: { id: ORDER, environment: "sandbox" },
      actor_assertion: { principal_id: `shopify-staff:${SHOP}/42`, provenance: "shopify_session_token" }, context: { shop: SHOP, preview: p },
    });
    expect(JSON.stringify(f.submitted())).not.toMatch(/ask_test|customerEmail|permit_token/);
    expect(f.posts()).toHaveLength(1);
    expect(f.posts()[0]?.init?.redirect).toBe("error");
  });

  it.each([
    { ...key(), org_id: "other-org" }, { ...key(), environment: "live" },
    { ...key(), scopes: ["connectors:read"] }, { ...key(), scopes: ["connectors:write"] },
    { ...key(), scopes: "connectors:read connectors:write" },
  ])("rejects mismatched/insufficient server credential %j before connector lookup or write", async (key) => {
    const f = fixture({ key });
    await expect(f.publish({ shop: SHOP, orderId: ORDER, preview: preview() })).rejects.toThrow();
    expect(f.calls).toHaveLength(1); expect(f.posts()).toHaveLength(0);
  });

  it.each([
    { ...connector(), id: "other-id" }, { ...connector(), org_id: "other-org" },
    { ...connector(), status: "revoked" }, { ...connector(), status: "error" },
    { ...connector(), revoked_at: NOW.toISOString() }, { ...connector(), environment: "production" },
    { ...connector(), connector_type: "github" }, { ...connector(), config: { provider: "shopify", shop_domain: "other.myshopify.com" } },
    { ...connector(), config: { provider: "other", shop_domain: SHOP } },
  ])("rejects an incorrect connector binding %j without writing", async (connector) => {
    const f = fixture({ connector });
    await expect(f.publish({ shop: SHOP, orderId: ORDER, preview: preview() })).rejects.toThrow();
    expect(f.posts()).toHaveLength(0);
  });

  it("rechecks connector status for every handoff", async () => {
    const c = connector(); const f = fixture({ connector: c });
    await f.publish({ shop: SHOP, orderId: ORDER, preview: preview() });
    c.status = "revoked";
    await expect(f.publish({ shop: SHOP, orderId: ORDER, preview: preview() })).rejects.toThrow();
    expect(f.posts()).toHaveLength(1);
  });

  it("refuses stale, future, changed-order and authorizing previews before contacting runtime", async () => {
    for (const p of [
      { ...preview(), read_at: new Date(NOW.getTime() - 61_000).toISOString() },
      { ...preview(), read_at: new Date(NOW.getTime() + 60_000).toISOString() },
      { ...preview(), observed: { ...preview().observed, order_id: "gid://shopify/Order/2002" } },
      { ...preview(), authorization: "allow" },
    ]) {
      const f = fixture();
      await expect(f.publish({ shop: SHOP, orderId: ORDER, preview: p as ReturnType<typeof preview> })).rejects.toThrow();
      expect(f.calls).toHaveLength(0);
    }
  });

  it("refuses a preview that expires during destination checks", async () => {
    let calls = 0; const f = fixture({ now: () => new Date(NOW.getTime() + (++calls === 1 ? 0 : 61_000)) });
    await expect(f.publish({ shop: SHOP, orderId: ORDER, preview: preview() })).rejects.toThrow("expired");
    expect(f.posts()).toHaveLength(0);
  });

  it.each([
    { organization_id: "other-org" }, { connector_id: "other-connector" }, { observation_id: "other-request" },
    { idempotency_key: "other-key" }, { event_id: "not-a-uuid" }, { authority_effect: "approved" },
    { execution: "succeeded" }, { verification: "verified" }, { permit_token: "forged" }, { received_at: "not-a-date" },
  ])("rejects a mismatched or authorizing receipt %j", async (patch) => {
    const f = fixture({ receipt: r => ({ ...r, ...patch }) });
    await expect(f.publish({ shop: SHOP, orderId: ORDER, preview: preview() })).rejects.toThrow("unconfirmed");
    expect(f.posts()).toHaveLength(1);
  });

  it("does not automatically retry an uncertain submission", async () => {
    const f = fixture({ postThrows: true });
    await expect(f.publish({ shop: SHOP, orderId: ORDER, preview: preview() })).rejects.toThrow();
    expect(f.posts()).toHaveLength(1);
  });
});
