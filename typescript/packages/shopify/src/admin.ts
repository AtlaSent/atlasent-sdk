/**
 * Minimal Shopify Admin GraphQL client: the two calls a gated refund needs.
 *
 * Field names follow the Admin GraphQL API (Order.fulfillments,
 * Fulfillment.displayStatus/deliveredAt, Order.transactions, refundCreate).
 * They have not been run against a live store from this package yet; check
 * them against the API version you pin before the first live refund.
 */

export const DEFAULT_ADMIN_API_VERSION = "2025-10";

export interface ShopifyMoney {
  amount: string;
  currencyCode: string;
}

export interface ShopifyFulfillment {
  id: string;
  status: string;
  displayStatus: string | null;
  deliveredAt: string | null;
}

export interface ShopifyTransaction {
  id: string;
  kind: string;
  status: string;
  gateway: string;
  amountSet: { shopMoney: ShopifyMoney };
  parentTransaction: { id: string } | null;
}

export interface ShopifyOrder {
  id: string;
  name: string;
  email: string | null;
  currencyCode: string;
  cancelledAt: string | null;
  fulfillments: ShopifyFulfillment[];
  transactions: ShopifyTransaction[];
}

export interface RefundTransactionInput {
  orderId: string;
  parentId: string;
  kind: "REFUND";
  gateway: string;
  amount: string;
}

export interface RefundCreateInput {
  orderId: string;
  note: string;
  notify: boolean;
  transactions: RefundTransactionInput[];
}

export interface CreatedRefund {
  id: string;
  createdAt: string | null;
  totalRefunded: ShopifyMoney | null;
}

/** What the guard needs from Shopify. Tests substitute a fake. */
export interface ShopifyAdmin {
  getOrder(orderId: string): Promise<ShopifyOrder | null>;
  createRefund(input: RefundCreateInput): Promise<CreatedRefund>;
}

export class ShopifyAdminError extends Error {
  override name = "ShopifyAdminError";
}

const ORDER_QUERY = `query AtlaSentRefundFacts($id: ID!) {
  order(id: $id) {
    id
    name
    email
    currencyCode
    cancelledAt
    fulfillments(first: 50) { id status displayStatus deliveredAt }
    transactions(first: 100) {
      id kind status gateway
      amountSet { shopMoney { amount currencyCode } }
      parentTransaction { id }
    }
  }
}`;

const REFUND_MUTATION = `mutation AtlaSentRefund($input: RefundInput!) {
  refundCreate(input: $input) {
    refund { id createdAt totalRefundedSet { shopMoney { amount currencyCode } } }
    userErrors { field message }
  }
}`;

export interface AdminClientOptions {
  /** `my-store.myshopify.com` */
  shop: string;
  accessToken: string;
  apiVersion?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
}

/** Accepts a numeric id or a full `gid://shopify/Order/<id>`. */
export function toOrderGid(orderId: string): string {
  const s = orderId.trim();
  if (/^gid:\/\/shopify\/Order\/\d+$/.test(s)) return s;
  if (/^\d+$/.test(s)) return `gid://shopify/Order/${s}`;
  throw new ShopifyAdminError(`not a Shopify order id: ${JSON.stringify(orderId)}`);
}

/** Longest input accepted; a myshopify.com domain is far shorter. */
const MAX_SHOP_INPUT = 255;

export function normalizeShopDomain(shop: string): string {
  if (shop.length > MAX_SHOP_INPUT) throw new ShopifyAdminError("shop domain too long");
  let s = shop.trim().toLowerCase();
  if (s.startsWith("https://")) s = s.slice(8);
  else if (s.startsWith("http://")) s = s.slice(7);
  // Strip trailing slashes without a backtracking regex (CodeQL js/polynomial-redos).
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 47) end--;
  s = s.slice(0, end);
  if (!/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/.test(s)) {
    throw new ShopifyAdminError(`not a myshopify.com domain: ${JSON.stringify(shop)}`);
  }
  return s;
}

export function createAdminClient(opts: AdminClientOptions): ShopifyAdmin {
  const shop = normalizeShopDomain(opts.shop);
  const version = opts.apiVersion ?? DEFAULT_ADMIN_API_VERSION;
  const doFetch = opts.fetch ?? fetch;
  const timeoutMs = opts.timeoutMs ?? 10_000;

  async function graphql<T>(query: string, variables: Record<string, unknown>): Promise<T> {
    const res = await doFetch(`https://${shop}/admin/api/${version}/graphql.json`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-shopify-access-token": opts.accessToken },
      body: JSON.stringify({ query, variables }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const body = (await res.json().catch(() => null)) as { data?: T; errors?: unknown } | null;
    if (!res.ok || body === null) throw new ShopifyAdminError(`Shopify Admin API HTTP ${res.status}`);
    if (body.errors !== undefined) throw new ShopifyAdminError(`Shopify Admin API error: ${JSON.stringify(body.errors)}`);
    if (body.data === undefined) throw new ShopifyAdminError("Shopify Admin API returned no data");
    return body.data;
  }

  return {
    async getOrder(orderId) {
      const data = await graphql<{ order: ShopifyOrder | null }>(ORDER_QUERY, { id: toOrderGid(orderId) });
      return data.order;
    },
    async createRefund(input) {
      const data = await graphql<{
        refundCreate: {
          refund: { id: string; createdAt: string | null; totalRefundedSet: { shopMoney: ShopifyMoney } | null } | null;
          userErrors: { field: string[] | null; message: string }[];
        };
      }>(REFUND_MUTATION, { input });
      const r = data.refundCreate;
      if (r.userErrors.length > 0) {
        throw new ShopifyAdminError(`refundCreate rejected: ${r.userErrors.map((e) => e.message).join("; ")}`);
      }
      if (r.refund === null) throw new ShopifyAdminError("refundCreate returned no refund");
      return { id: r.refund.id, createdAt: r.refund.createdAt, totalRefunded: r.refund.totalRefundedSet?.shopMoney ?? null };
    },
  };
}
