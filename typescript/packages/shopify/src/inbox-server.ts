/** Explicit internal/test Observe integration. Default serve stays standalone/read-only. */
import { createServer } from "node:http";
import { pathToFileURL } from "node:url";
import { normalizeShopDomain } from "./admin.js";
import { createPreviewObservationPublisher } from "./action-inbox.js";
import { createOperationsPreviewHandler } from "./preview-server.js";
import { tokenExchangeAdmin } from "./token-exchange-admin.js";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const clientId = requireEnv("SHOPIFY_CLIENT_ID");
  const clientSecret = requireEnv("SHOPIFY_CLIENT_SECRET");
  const shop = normalizeShopDomain(requireEnv("SHOPIFY_SHOP"));
  const environment = requireEnv("ATLASENT_INBOX_ENVIRONMENT");
  if (environment !== "test" && environment !== "live") throw new Error("ATLASENT_INBOX_ENVIRONMENT must be test or live");
  const orgId = requireEnv("ATLASENT_INBOX_ORG_ID");
  const connectorId = requireEnv("ATLASENT_INBOX_CONNECTOR_ID");
  const publishObservation = createPreviewObservationPublisher({
    baseUrl: requireEnv("ATLASENT_INBOX_BASE_URL"), apiKey: requireEnv("ATLASENT_INBOX_API_KEY"),
    orgId, connectorId, environment,
  });
  const port = Number(process.env.PORT ?? 3000);
  createServer(createOperationsPreviewHandler({
    clientId, clientSecret, allowedShops: [shop],
    adminFor: tokenExchangeAdmin({ clientId, clientSecret }), publishObservation, observationDestination: { orgId, connectorId },
  })).listen(port, () => console.log(`AtlaSent order preview with explicit Observe handoff listening on :${port} for ${shop}`));
}
