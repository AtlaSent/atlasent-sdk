import { describe, expect, it } from "vitest";
import { createAdminClient, DEFAULT_ADMIN_API_VERSION } from "../src/admin.js";
import { tokenExchangeAdmin } from "../src/server.js";

function fakeShopifyHttp(exchange: Array<{ access_token: string; expires_in?: number }>) {
  const exchanges: Record<string, unknown>[] = [];
  const queries: { token: string | null; query: string }[] = [];
  const impl = (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    const body = JSON.parse(String(init?.body ?? "{}"));
    if (u.endsWith("/admin/oauth/access_token")) {
      exchanges.push(body);
      const next = exchange.shift();
      return new Response(JSON.stringify(next ?? {}), { status: next ? 200 : 400 });
    }
    queries.push({ token: new Headers(init?.headers).get("x-shopify-access-token"), query: body.query });
    return new Response(JSON.stringify({ data: { order: null } }), { status: 200, headers: { "x-shopify-api-version": DEFAULT_ADMIN_API_VERSION } });
  }) as typeof fetch;
  return { impl, exchanges, queries };
}

describe("tokenExchangeAdmin", () => {
  it("requests an expiring offline token and re-exchanges once it is about to expire", async () => {
    let clock = 0;
    const http = fakeShopifyHttp([
      { access_token: "tok-1", expires_in: 3600 },
      { access_token: "tok-2", expires_in: 3600 },
    ]);
    const adminFor = tokenExchangeAdmin({ clientId: "c", clientSecret: "s", fetch: http.impl, now: () => clock });

    await (await adminFor("pinecone.myshopify.com", "id-1")).getOrder("1");
    clock = 3_000_000; // 50 min: still cached
    await (await adminFor("pinecone.myshopify.com", "id-2")).getOrder("1");
    clock = 3_550_000; // inside the one-minute safety margin
    await (await adminFor("pinecone.myshopify.com", "id-3")).getOrder("1");

    expect(http.exchanges).toHaveLength(2);
    expect(http.exchanges[0]).toMatchObject({ expiring: "1", subject_token: "id-1", requested_token_type: "urn:shopify:params:oauth:token-type:offline-access-token" });
    expect(http.exchanges[1]).toMatchObject({ subject_token: "id-3" });
    expect(http.queries.map((q) => q.token)).toEqual(["tok-1", "tok-1", "tok-2"]);
  });

  it("caches a non-expiring token", async () => {
    const http = fakeShopifyHttp([{ access_token: "tok" }]);
    const adminFor = tokenExchangeAdmin({ clientId: "c", clientSecret: "s", fetch: http.impl, now: () => 1e12 });
    await adminFor("pinecone.myshopify.com", "a");
    await adminFor("pinecone.myshopify.com", "b");
    expect(http.exchanges).toHaveLength(1);
  });

  it("fails when the exchange fails", async () => {
    const http = fakeShopifyHttp([]);
    const adminFor = tokenExchangeAdmin({ clientId: "c", clientSecret: "s", fetch: http.impl });
    await expect(adminFor("pinecone.myshopify.com", "a")).rejects.toThrow(/token exchange failed/);
  });
});

describe("the order query", () => {
  it("asks for the customer email only when told to", async () => {
    const http = fakeShopifyHttp([]);
    const admin = createAdminClient({ shop: "pinecone.myshopify.com", accessToken: "t", fetch: http.impl });
    await admin.getOrder("1");
    await admin.getOrder("1", { includeEmail: true });
    expect(http.queries[0]!.query).not.toMatch(/\bemail\b/);
    expect(http.queries[1]!.query).toMatch(/\bemail\b/);
  });
});

