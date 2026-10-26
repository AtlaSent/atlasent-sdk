import { createAdminClient, type ShopifyAdmin } from "./admin.js";

/**
 * Admin API access via Shopify token exchange: trade the staff member's
 * session token for an offline access token.
 *
 * Requests an expiring token (`expiring: "1"`) and caches it only until
 * shortly before `expires_in`. Every request to this backend carries a fresh
 * session token, so an expired token is simply exchanged again; no refresh
 * token is stored. A response without `expires_in` (a non-expiring token)
 * is cached for the life of the process.
 */
export function tokenExchangeAdmin(opts: {
  clientId: string;
  clientSecret: string;
  apiVersion?: string;
  fetch?: typeof fetch;
  now?: () => number;
}) {
  const cache = new Map<string, { token: string; expiresAt: number }>();
  const doFetch = opts.fetch ?? fetch;
  const now = opts.now ?? Date.now;
  return async (shop: string, sessionToken: string): Promise<ShopifyAdmin> => {
    const hit = cache.get(shop);
    let accessToken = hit !== undefined && hit.expiresAt > now() ? hit.token : undefined;
    if (accessToken === undefined) {
      const res = await doFetch(`https://${shop}/admin/oauth/access_token`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({
          client_id: opts.clientId,
          client_secret: opts.clientSecret,
          grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
          subject_token: sessionToken,
          subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
          requested_token_type: "urn:shopify:params:oauth:token-type:offline-access-token",
          expiring: "1",
        }),
        signal: AbortSignal.timeout(10_000),
      });
      const body = (await res.json().catch(() => null)) as { access_token?: string; expires_in?: number } | null;
      if (!res.ok || typeof body?.access_token !== "string") throw new Error(`token exchange failed: HTTP ${res.status}`);
      accessToken = body.access_token;
      const ttlMs = typeof body.expires_in === "number" && body.expires_in > 0 ? body.expires_in * 1000 : Infinity;
      // Refresh a minute early so a token never expires mid-refund.
      cache.set(shop, { token: accessToken, expiresAt: now() + Math.max(0, ttlMs - 60_000) });
    }
    return createAdminClient({
      shop,
      accessToken,
      ...(opts.apiVersion ? { apiVersion: opts.apiVersion } : {}),
      fetch: doFetch,
    });
  };
}
