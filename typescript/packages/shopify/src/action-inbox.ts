/** Explicit, server-configured Observe handoff; never evaluates or issues a refund. */
import { randomUUID } from "node:crypto";
import { AtlaSentClient } from "@atlasent/sdk";
import { normalizeShopDomain } from "./admin.js";
import type { RefundOperationsPreview } from "./operations-preview.js";

export interface PreviewObservationInput {
  shop: string;
  orderId: string;
  userId?: string;
  preview: RefundOperationsPreview;
}

export interface PreviewObservationReceipt {
  schema: "atlasent.connector-observation-receipt.v1";
  event_id: string;
  observation_id: string;
  idempotency_key: string;
  organization_id: string;
  connector_id: string;
  received_at: string;
  capability_level: "observe";
  authority_effect: "none";
  execution: "not_attempted";
  verification: "not_performed";
  duplicate: boolean;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function createPreviewObservationPublisher(opts: {
  /** Exact runtime functions root, e.g. https://<staging>.supabase.co/functions/v1. */
  baseUrl: string;
  apiKey: string;
  orgId: string;
  connectorId: string;
  environment: "test" | "live";
  fetch?: typeof fetch;
  now?: () => Date;
}) {
  const config = { ...opts };
  const base = new URL(config.baseUrl);
  if (base.protocol !== "https:" || base.username || base.password || base.search || base.hash ||
      base.pathname.replace(/\/+$/, "") !== "/functions/v1" || !["test", "live"].includes(config.environment) || !UUID.test(config.orgId) || !UUID.test(config.connectorId)) {
    throw new Error("An exact HTTPS runtime functions root, organization and connector are required");
  }
  const baseUrl = base.href.replace(/\/+$/, "");
  const doFetch = config.fetch ?? fetch;
  const client = new AtlaSentClient({ baseUrl, apiKey: config.apiKey, fetch: doFetch });
  const headers = { authorization: `Bearer ${config.apiKey}`, "content-type": "application/json" };

  return async (input: PreviewObservationInput): Promise<PreviewObservationReceipt> => {
    const shop = normalizeShopDomain(input.shop);
    const preview = input.preview;
    const age = (config.now?.() ?? new Date()).getTime() - Date.parse(preview.read_at);
    if (preview.schema !== "atlasent.shopify_refund_operations_preview.v1" || preview.mode !== "read_only" ||
      preview.authorization !== "not_evaluated" || preview.execution !== "not_attempted" || preview.customer_notification !== "not_sent" ||
      preview.observed.order_id !== input.orderId || !Number.isFinite(age) || age < -5000 || age > 60_000) {
      throw new Error("A fresh, matching read-only preview is required");
    }

    // Re-read each time. No cached tenant, revoked credential or connector status.
    const key = await client.keySelf();
    if (key.orgId !== config.orgId || key.environment !== config.environment ||
      !Array.isArray(key.scopes) || !key.scopes.includes("connectors:read") || !key.scopes.includes("connectors:write")) {
      throw new Error("The server credential does not match the configured observation destination");
    }
    const connectorResponse = await doFetch(`${baseUrl}/v1-connectors/${config.connectorId}`, {
      headers, redirect: "error", signal: AbortSignal.timeout(10_000),
    });
    const c = await connectorResponse.json().catch(() => null);
    const environment = c?.environment;
    if (!connectorResponse.ok || !c || c.id !== config.connectorId || c.org_id !== config.orgId ||
      c.status !== "active" || c.revoked_at != null || c.connector_type !== "custom" ||
      c.config?.provider !== "shopify" || c.config?.shop_domain !== shop ||
      !(config.environment === "live" ? environment === "production" : environment === "sandbox" || environment === "staging")) {
      throw new Error("The active Shopify connector does not match the shop, organization and environment");
    }
    const writeAge = (config.now?.() ?? new Date()).getTime() - Date.parse(preview.read_at);
    if (!Number.isFinite(writeAge) || writeAge < -5000 || writeAge > 60_000) throw new Error("The preview expired before submission");
    const observationId = randomUUID();
    const observation = {
      schema_version: "connector-observation.v1",
      event_id: observationId,
      idempotency_key: observationId,
      organization_id: config.orgId,
      connector_id: config.connectorId,
      source_system: "shopify",
      capability_level: "observe",
      observed_at: preview.read_at,
      action: { slug: "customer.refund.issue", mapping_version: "shopify-refund-preview.v1" },
      target: { id: input.orderId, type: "shopify_order", environment },
      // Provider assertion only; this is never an AtlaSent verified actor identity.
      actor_assertion: {
        principal_id: `shopify-staff:${shop}/${input.userId ?? "unknown"}`,
        principal_kind: "human",
        provenance: "shopify_session_token",
      },
      context: { shop, preview },
    };
    // No POST retry after an uncertain response, and no generic /ingest call:
    // that path also invokes cross-system enforcement. Observe owns no decision.
    const response = await doFetch(`${baseUrl}/v1-connectors/${config.connectorId}/observations`, {
      method: "POST", headers, redirect: "error", signal: AbortSignal.timeout(10_000),
      body: JSON.stringify(observation),
    });
    const receipt = await response.json().catch(() => null);
    if (!response.ok || !receipt || receipt.schema !== "atlasent.connector-observation-receipt.v1" ||
      !UUID.test(receipt.event_id) || receipt.observation_id !== observationId || receipt.idempotency_key !== observationId ||
      receipt.organization_id !== config.orgId || receipt.connector_id !== config.connectorId ||
      receipt.capability_level !== "observe" || receipt.authority_effect !== "none" ||
      receipt.execution !== "not_attempted" || receipt.verification !== "not_performed" ||
      typeof receipt.received_at !== "string" || !Number.isFinite(Date.parse(receipt.received_at)) || typeof receipt.duplicate !== "boolean" ||
      ["decision", "permit_id", "permit_token", "approval_satisfied", "verified"].some((key) => Object.hasOwn(receipt, key))) {
      throw new Error("Action Inbox receipt unavailable; submission outcome is unconfirmed");
    }
    return receipt as PreviewObservationReceipt;
  };
}
