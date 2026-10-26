import React from "react";
import TestRenderer, { act } from "react-test-renderer";
import { afterEach, describe, expect, it, vi } from "vitest";
import Action from "../app/extensions/atlasent-refund/src/ActionExtension.jsx";
import { setAdminApi } from "./fixtures/shopify-admin.jsx";

const ORG = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", CONNECTOR = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const ORDER = "gid://shopify/Order/1001";
const preview = () => ({
  schema: "atlasent.shopify_refund_operations_preview.v1", mode: "read_only", authorization: "not_evaluated", execution: "not_attempted", customer_notification: "not_sent",
  disposition: "routine_candidate", next_step: "verify_business_eligibility", read_at: "2026-10-26T01:00:00Z",
  operator_message: "Checks still required", missing_proofs: ["independent_authority_and_approval"],
  observed: { order_id: ORDER, currency: "USD", order_status: "delivered", requested_cents: 1899, refundable_cents: 3500 },
  inbox_destination: { organization_id: ORG, connector_id: CONNECTOR },
});
const receipt = () => ({
  schema: "atlasent.connector-observation-receipt.v1", event_id: "cccccccc-cccc-cccc-cccc-cccccccccccc",
  observation_id: "dddddddd-dddd-dddd-dddd-dddddddddddd", idempotency_key: "dddddddd-dddd-dddd-dddd-dddddddddddd",
  organization_id: ORG, connector_id: CONNECTOR, received_at: "2026-10-26T01:00:01Z",
  capability_level: "observe", authority_effect: "none", execution: "not_attempted", verification: "not_performed", duplicate: false,
});
const response = (body, status = 200) => new Response(JSON.stringify(body), { status });
let tree;
afterEach(() => { if (tree) act(() => tree.unmount()); tree = undefined; vi.unstubAllGlobals(); });
const button = label => tree.root.findAllByType("button").find(b => b.children.join("") === label);

async function start() {
  let complete;
  const pending = new Promise(resolve => { complete = resolve; });
  const fetch = vi.fn(async path => path.endsWith("/inbox") ? pending : response(preview()));
  vi.stubGlobal("fetch", fetch);
  const api = { data: { selected: [{ id: ORDER }] }, auth: { idToken: async () => "synthetic-session" }, close: vi.fn() };
  setAdminApi(api);
  act(() => { tree = TestRenderer.create(React.createElement(Action)); });
  act(() => tree.root.findByType("input").props.onChange("18.99"));
  await act(async () => { await button("Preview next step (read only)").props.onPress(); });
  await act(async () => { void button("Add fresh preview to AtlaSent Inbox").props.onPress(); await Promise.resolve(); });
  return { api, fetch, complete };
}

describe("pending observation UI outcomes", () => {
  it("locks edits and close while a handoff is pending, including a forced onChange", async () => {
    const f = await start();
    expect(tree.root.findByType("input").props.disabled).toBe(true);
    expect(button("Close").props.disabled).toBe(true);
    act(() => tree.root.findByType("input").props.onChange("99.00"));
    expect(tree.root.findByType("input").props.value).toBe("18.99");
    await act(async () => { f.complete(response({ preview: preview(), receipt: receipt() })); });
    expect(JSON.stringify(tree.toJSON())).toContain("Observation recorded in Action Inbox history");
    expect(button("Close").props.disabled).toBe(false);
  });

  it("preserves the original order's receipt when the host selects another order mid-write", async () => {
    const f = await start();
    f.api.data.selected[0].id = "gid://shopify/Order/2002";
    act(() => tree.update(React.createElement(Action)));
    expect(button("Close").props.disabled).toBe(true);
    await act(async () => { f.complete(response({ preview: preview(), receipt: receipt() })); });
    const rendered = JSON.stringify(tree.toJSON());
    expect(rendered).toContain("Observation recorded in Action Inbox history");
    expect(rendered).toContain(ORDER);
    expect(rendered).toContain(receipt().event_id);
    expect(rendered).not.toContain("gid://shopify/Order/2002");
    expect(f.fetch.mock.calls.filter(([path]) => path.endsWith("/inbox"))).toHaveLength(1);
  });

  it("preserves an unconfirmed-write warning for its original order after a selection change", async () => {
    const f = await start();
    f.api.data.selected[0].id = "gid://shopify/Order/2002";
    act(() => tree.update(React.createElement(Action)));
    await act(async () => { f.complete(response({ error: "uncertain" }, 503)); });
    const rendered = JSON.stringify(tree.toJSON());
    expect(rendered).toContain("Inbox submission outcome unconfirmed");
    expect(rendered).toContain("Check Action Inbox History before submitting again");
    expect(rendered).toContain(ORDER);
    expect(rendered).not.toContain("Observation recorded in Action Inbox history");
  });
});
