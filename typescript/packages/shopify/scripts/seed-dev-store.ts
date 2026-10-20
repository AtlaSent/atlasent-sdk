/**
 * Creates the five demo scenarios as orders in a Shopify DEVELOPMENT store.
 *
 *   SHOPIFY_SHOP=pinecone-demo.myshopify.com SHOPIFY_ADMIN_TOKEN=... \
 *   npm run seed-dev-store -- [--dry-run]
 *
 * Each order is paid with a "manual" gateway transaction, so refunding it
 * records a refund without moving real money. Delivery is simulated with a
 * fulfillment plus a DELIVERED (or IN_TRANSIT) fulfillment event dated in
 * the past. After seeding, the script reads each order back and prints the
 * facts the gate would see, so you can confirm delivery registered.
 *
 * Needs an access token with order and fulfillment write scopes (see README).
 * Not yet run against a live store: check the mutations against the API
 * version you pin. Refuses to run without SHOPIFY_SEED_CONFIRM=dev-store.
 */

import { parseArgs } from "node:util";
import { createAdminClient, DEFAULT_ADMIN_API_VERSION, normalizeShopDomain } from "../src/admin.js";
import { centsToMoney, deriveRefundFacts } from "../src/facts.js";

interface Scenario {
  label: string;
  email: string;
  item: string;
  price: string;
  delivery: "delivered" | "in_transit";
  daysAgo: number;
}

export const SCENARIOS: Scenario[] = [
  { label: "Chew toy arrived torn ($18.99 → refunded)", email: "robin@example.com", item: "Rope chew toy", price: "34.99", delivery: "delivered", daysAgo: 5 },
  { label: "Wrong size cat tree ($72.00 → manager)", email: "sam@example.com", item: "Cat tree, large", price: "129.00", delivery: "delivered", daysAgo: 3 },
  { label: "Still in transit ($12.00 → denied)", email: "kai@example.com", item: "Bird seed, 2kg", price: "24.50", delivery: "in_transit", daysAgo: 1 },
  { label: "45 days after delivery ($25.00 → denied)", email: "alex@example.com", item: "Aquarium filter", price: "42.00", delivery: "delivered", daysAgo: 45 },
  { label: "Treats arrived stale ($19.99 → refunded)", email: "jo@example.com", item: "Salmon treats", price: "19.99", delivery: "delivered", daysAgo: 10 },
];

const ORDER_CREATE = `mutation SeedOrder($order: OrderCreateOrderInput!) {
  orderCreate(order: $order, options: { sendReceipt: false, sendFulfillmentReceipt: false }) {
    order { id name fulfillmentOrders(first: 5) { nodes { id } } }
    userErrors { field message }
  }
}`;

const FULFILL = `mutation SeedFulfill($fulfillment: FulfillmentInput!) {
  fulfillmentCreate(fulfillment: $fulfillment) {
    fulfillment { id }
    userErrors { field message }
  }
}`;

const EVENT = `mutation SeedEvent($event: FulfillmentEventInput!) {
  fulfillmentEventCreate(fulfillmentEvent: $event) {
    fulfillmentEvent { id status }
    userErrors { field message }
  }
}`;

function env(name: string): string {
  const v = process.env[name];
  if (!v) {
    console.error(`${name} is required`);
    process.exit(2);
  }
  return v;
}

async function main(): Promise<void> {
  const { values } = parseArgs({ options: { "dry-run": { type: "boolean" } } });
  if (values["dry-run"]) {
    for (const s of SCENARIOS) console.log(`would create: ${s.label} — ${s.item} $${s.price}, ${s.delivery} ${s.daysAgo}d ago, ${s.email}`);
    return;
  }
  if (process.env.SHOPIFY_SEED_CONFIRM !== "dev-store") {
    console.error("Refusing to seed: set SHOPIFY_SEED_CONFIRM=dev-store to confirm this is a development store.");
    process.exit(2);
  }

  const shop = normalizeShopDomain(env("SHOPIFY_SHOP"));
  const token = env("SHOPIFY_ADMIN_TOKEN");
  const version = process.env.SHOPIFY_API_VERSION ?? DEFAULT_ADMIN_API_VERSION;

  async function gql<T>(query: string, variables: Record<string, unknown>): Promise<T> {
    const res = await fetch(`https://${shop}/admin/api/${version}/graphql.json`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-shopify-access-token": token },
      body: JSON.stringify({ query, variables }),
    });
    const body = (await res.json()) as { data?: T; errors?: unknown };
    if (!res.ok || body.errors || !body.data) throw new Error(`HTTP ${res.status}: ${JSON.stringify(body.errors ?? body)}`);
    return body.data;
  }
  const check = (op: string, errs: { message: string }[]) => {
    if (errs.length) throw new Error(`${op}: ${errs.map((e) => e.message).join("; ")}`);
  };

  const admin = createAdminClient({ shop, accessToken: token, apiVersion: version });
  const now = Date.now();

  for (const s of SCENARIOS) {
    const created = await gql<{
      orderCreate: { order: { id: string; name: string; fulfillmentOrders: { nodes: { id: string }[] } } | null; userErrors: { message: string }[] };
    }>(ORDER_CREATE, {
      order: {
        email: s.email,
        currency: "USD",
        lineItems: [{ title: s.item, quantity: 1, requiresShipping: true, priceSet: { shopMoney: { amount: s.price, currencyCode: "USD" } } }],
        transactions: [{ kind: "SALE", status: "SUCCESS", gateway: "manual", amountSet: { shopMoney: { amount: s.price, currencyCode: "USD" } } }],
      },
    });
    check("orderCreate", created.orderCreate.userErrors);
    const order = created.orderCreate.order!;
    const fo = order.fulfillmentOrders.nodes[0];
    if (!fo) throw new Error(`${order.name}: no fulfillment order was created`);

    const f = await gql<{ fulfillmentCreate: { fulfillment: { id: string } | null; userErrors: { message: string }[] } }>(FULFILL, {
      fulfillment: { lineItemsByFulfillmentOrder: [{ fulfillmentOrderId: fo.id }], notifyCustomer: false, trackingInfo: { company: "Demo Carrier", number: `DEMO-${order.name}` } },
    });
    check("fulfillmentCreate", f.fulfillmentCreate.userErrors);

    const ev = await gql<{ fulfillmentEventCreate: { userErrors: { message: string }[] } }>(EVENT, {
      event: {
        fulfillmentId: f.fulfillmentCreate.fulfillment!.id,
        status: s.delivery === "delivered" ? "DELIVERED" : "IN_TRANSIT",
        happenedAt: new Date(now - s.daysAgo * 86_400_000).toISOString(),
      },
    });
    check("fulfillmentEventCreate", ev.fulfillmentEventCreate.userErrors);

    const back = await admin.getOrder(order.id);
    const facts = back ? deriveRefundFacts(back, new Date()) : null;
    console.log(
      `${order.name} ${order.id}  ${s.label}\n    gate sees: ${facts ? `${facts.order_status}${facts.days_since_delivery !== undefined ? `, ${facts.days_since_delivery} days` : ""}, refundable $${centsToMoney(facts.refundable_cents)}` : "order not readable"}`,
    );
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
