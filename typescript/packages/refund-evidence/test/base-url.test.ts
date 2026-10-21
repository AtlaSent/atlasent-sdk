import { describe, expect, it } from "vitest";
import { resolveBaseUrl } from "../../../src/baseUrl.js";
import { HOSTED_RUNTIME_HOSTS } from "../../../src/functionRegion.js";
import { resolveRuntimeBaseUrl as stripeResolve } from "../../stripe/src/approvals.js";
import { resolveRuntimeBaseUrl as shopifyResolve } from "../../shopify/src/approvals.js";
import { fetchKeyCheck } from "../src/preflight.js";

const INPUTS = [
  "https://api.atlasent.io",
  "https://api.atlasent.io/",
  "https://API.atlasent.io//",
  "https://api.atlasent.io/functions/v1",
  "https://api.atlasent.io/functions/v1/",
  "https://lwnqpmnxpeyhpxvastku.supabase.co",
  "https://kttccumlnmdtupgbyfue.supabase.co/",
  "https://lwnqpmnxpeyhpxvastku.supabase.co/functions/v1",
  "https://api.atlasent.io/?x=1",
  "https://self-hosted.example.com",
  "https://proxy.example.com/atlasent/",
  "not a url///",
  ...[...HOSTED_RUNTIME_HOSTS].map((h) => `https://${h}`),
];

describe("the refund packages resolve a base URL exactly as the SDK does", () => {
  it.each(INPUTS)("%s", (input) => {
    expect(stripeResolve(input)).toBe(resolveBaseUrl(input));
    expect(shopifyResolve(input)).toBe(resolveBaseUrl(input));
  });

  it("preflight's key check reaches /functions/v1 from a bare hosted URL", async () => {
    const urls: string[] = [];
    const f = (async (url: string) => {
      urls.push(url);
      return new Response(JSON.stringify({ valid: true, org_id: "o", key_id: "k", environment: "test", scopes: [] }), { status: 200 });
    }) as unknown as typeof fetch;
    await fetchKeyCheck(f, { apiKey: "k", baseUrl: "https://api.atlasent.io" });
    await fetchKeyCheck(f, { apiKey: "k", baseUrl: "https://proxy.example.com/rt/" });
    expect(urls).toEqual(["https://api.atlasent.io/functions/v1/v1-api-keys/check", "https://proxy.example.com/rt/v1-api-keys/check"]);
  });
});
