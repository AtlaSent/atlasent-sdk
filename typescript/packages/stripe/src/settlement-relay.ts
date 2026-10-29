/**
 * The relay that carries Stripe's refund events to AtlaSent, so a verified
 * provider outcome can settle a refund reservation (RF4,
 * AtlaSent/atlasent-api#4779):
 *
 *   POST /webhooks/stripe/settlement   Stripe-Signature -> forward -> answer Stripe
 *   GET  /healthz
 *
 * Stripe cannot attach an AtlaSent API key, so this endpoint receives the
 * delivery and forwards the exact bytes and `Stripe-Signature` header to
 * `POST {base}/v1-assertion-ingest/stripe?connector_id=<id>` with an
 * `assertions:write` key. AtlaSent verifies the signature again, under the
 * connector credential an owner or admin pinned as the settlement source,
 * and decides everything itself. The relay carries events; it cannot settle,
 * approve or refund anything.
 *
 * Run it as its own Stripe endpoint, with its own signing secret: the secret
 * enrolled on the pinned connector. Keep it apart from the alarm
 * (webhook-server.ts), so a redelivery here never re-runs the alarm, and keep
 * the secret off the agent that requests refunds.
 *
 * Stripe gets a 2xx only when AtlaSent recorded an outcome for the event:
 * settled, already settled, not terminal yet, or a final refusal. Anything
 * else (AtlaSent unreachable, a non-2xx, a response with no settlement
 * outcome) is non-2xx, so Stripe delivers the event again and its dashboard
 * shows the endpoint failing. One event settles at most once, so a
 * redelivery is safe. A delivery whose signature does not verify here is
 * refused and never reaches AtlaSent.
 */

import { createServer, type IncomingMessage, type RequestListener, type ServerResponse } from "node:http";
import { pathToFileURL } from "node:url";
import { DEFAULT_APPROVALS_BASE_URL, resolveRuntimeBaseUrl } from "./approvals.js";
import { verifyStripeSignature } from "./webhook.js";

/** Stripe event types whose `data.object` is a Refund: the ones AtlaSent can settle from. */
export const SETTLEMENT_EVENT_TYPES: ReadonlySet<string> = new Set([
  "refund.created",
  "refund.updated",
  "refund.failed",
  "charge.refund.updated",
]);

/** Outcomes AtlaSent recorded for the event. A redelivery would change nothing. */
const RECORDED_DISPOSITIONS: ReadonlySet<string> = new Set([
  "consumed",
  "released",
  "not_terminal",
  "duplicate_event",
  "already_settled",
  "refused",
]);

export const SETTLEMENT_RELAY_PATH = "/webhooks/stripe/settlement";

const MAX_BODY = 256 * 1024;
const MAX_RESPONSE = 64 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "[::1]"]);

export interface SettlementRelayConfig {
  /** The Stripe endpoint's signing secret: the one enrolled on the pinned connector. */
  webhookSecret: string;
  /** An AtlaSent API key with `assertions:write`, for the environment the connector is in. */
  apiKey: string;
  /** The Stripe connector an owner or admin pinned as the settlement source. */
  connectorId: string;
  /** AtlaSent runtime functions root. Defaults to the hosted runtime. */
  baseUrl?: string;
  fetch?: typeof fetch;
  /** Per-delivery limit on the AtlaSent call. Defaults to 8 s, inside Stripe's own timeout. */
  timeoutMs?: number;
  now?: () => Date;
  /** One line per delivery. Never receives the body, the signature or the key. */
  log?: (line: Record<string, unknown>) => void;
}

export interface RelayResponse {
  status: number;
  body: Record<string, unknown>;
}

export class SettlementRelayConfigError extends Error {
  override name = "SettlementRelayConfigError";
}

/** Validates the configuration and returns the ingest URL. Throws before anything listens. */
export function settlementIngestUrl(config: Pick<SettlementRelayConfig, "webhookSecret" | "apiKey" | "connectorId" | "baseUrl">): string {
  if (typeof config.webhookSecret !== "string" || config.webhookSecret.length === 0) {
    throw new SettlementRelayConfigError("the Stripe endpoint signing secret is required");
  }
  if (typeof config.apiKey !== "string" || config.apiKey.trim().length === 0) {
    throw new SettlementRelayConfigError("an AtlaSent API key with assertions:write is required");
  }
  if (typeof config.connectorId !== "string" || !UUID.test(config.connectorId)) {
    throw new SettlementRelayConfigError("the settlement connector id must be the connector's UUID");
  }
  const base = resolveRuntimeBaseUrl(config.baseUrl ?? DEFAULT_APPROVALS_BASE_URL);
  let parsed: URL;
  try {
    parsed = new URL(base);
  } catch {
    throw new SettlementRelayConfigError("the AtlaSent base URL is not a URL");
  }
  // The key travels with every delivery: never in clear text off this machine.
  const plaintextLoopback = parsed.protocol === "http:" && LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase());
  if (parsed.protocol !== "https:" && !plaintextLoopback) {
    throw new SettlementRelayConfigError("the AtlaSent base URL must be https (plain http only for localhost)");
  }
  if (parsed.search !== "" || parsed.hash !== "" || parsed.username !== "" || parsed.password !== "") {
    throw new SettlementRelayConfigError("the AtlaSent base URL must not carry a query, fragment or credentials");
  }
  return `${base}/v1-assertion-ingest/stripe?connector_id=${encodeURIComponent(config.connectorId.toLowerCase())}`;
}

function defaultLog(line: Record<string, unknown>): void {
  console.log(JSON.stringify(line));
}

/** Stop reading at the byte limit rather than buffering an unbounded body. */
async function readIngestResponse(res: Response): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const decoder = new TextDecoder();
  let size = 0;
  let text = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return text + decoder.decode();
      size += value.byteLength;
      if (size > MAX_RESPONSE) {
        await reader.cancel().catch(() => {});
        throw new Error("AtlaSent response too large");
      }
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }
}

/**
 * Handles one Stripe delivery and returns what to answer Stripe. Never
 * throws: every failure is a response, and a non-2xx one unless AtlaSent
 * recorded an outcome.
 */
export async function relayStripeEvent(
  rawBody: Buffer,
  signatureHeader: string | undefined,
  config: SettlementRelayConfig,
): Promise<RelayResponse> {
  const log = config.log ?? defaultLog;
  let url: string;
  try {
    url = settlementIngestUrl(config);
  } catch (err) {
    // Misconfigured: refuse rather than forward somewhere unintended.
    log({ event: "stripe_settlement_relay", outcome: "misconfigured", error: err instanceof Error ? err.message : String(err) });
    return { status: 500, body: { error: "relay_misconfigured" } };
  }

  if (!verifyStripeSignature(rawBody, signatureHeader, config.webhookSecret, config.now ? { now: config.now() } : {})) {
    log({ event: "stripe_settlement_relay", outcome: "bad_signature" });
    return { status: 400, body: { error: "bad signature" } };
  }

  let eventId: string | null = null;
  let eventType: string;
  try {
    const event = JSON.parse(rawBody.toString("utf8")) as { id?: unknown; type?: unknown };
    if (typeof event !== "object" || event === null || typeof event.type !== "string") throw new Error("no event type");
    eventType = event.type;
    if (typeof event.id === "string" && /^evt_[A-Za-z0-9_]{1,255}$/.test(event.id)) eventId = event.id;
  } catch {
    log({ event: "stripe_settlement_relay", outcome: "invalid_event" });
    return { status: 400, body: { error: "invalid event" } };
  }
  const base = { event: "stripe_settlement_relay", stripe_event_id: eventId, stripe_event_type: eventType };

  if (!SETTLEMENT_EVENT_TYPES.has(eventType)) {
    log({ ...base, outcome: "ignored" });
    return { status: 200, body: { ignored: true, reason: "not a refund event" } };
  }

  let res: Response;
  try {
    res = await (config.fetch ?? fetch)(url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${config.apiKey}`,
        "content-type": "application/json",
        // Exactly as Stripe sent it: AtlaSent verifies it over these exact bytes.
        "stripe-signature": signatureHeader as string,
      },
      body: new Uint8Array(rawBody),
      // A redirect would carry the key somewhere else.
      redirect: "error",
      signal: AbortSignal.timeout(config.timeoutMs ?? 8_000),
    });
  } catch (err) {
    log({ ...base, outcome: "atlasent_unreachable", error: err instanceof Error ? err.name : "error" });
    return { status: 503, body: { error: "atlasent_unreachable", retry: true } };
  }

  let text: string;
  try {
    text = await readIngestResponse(res);
  } catch {
    log({ ...base, outcome: "atlasent_response_unreadable", upstream_status: res.status });
    return { status: 502, body: { error: "atlasent_response_unreadable", retry: true } };
  }

  if (res.status < 200 || res.status > 299) {
    // Includes 503 refund_settlement_unavailable: nothing was recorded, deliver again.
    log({ ...base, outcome: "atlasent_rejected_delivery", upstream_status: res.status });
    return { status: res.status === 503 ? 503 : 502, body: { error: "atlasent_rejected_delivery", upstream_status: res.status, retry: true } };
  }

  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    log({ ...base, outcome: "atlasent_response_unreadable", upstream_status: res.status });
    return { status: 502, body: { error: "atlasent_response_unreadable", retry: true } };
  }

  const settlement = typeof json === "object" && json !== null ? (json as Record<string, unknown>).refund_settlement : undefined;
  const disposition =
    typeof settlement === "object" && settlement !== null ? (settlement as Record<string, unknown>).disposition : undefined;
  if (typeof disposition !== "string") {
    // AtlaSent accepted the bytes but did not verify them under the connector's
    // current secret: wrong connector id, a secret that differs from this
    // endpoint's, or a key for the other environment. Nothing settled.
    log({ ...base, outcome: "not_verified_by_connector", upstream_status: res.status });
    return { status: 502, body: { error: "not_verified_by_connector", retry: true } };
  }
  if (!RECORDED_DISPOSITIONS.has(disposition)) {
    log({ ...base, outcome: "unrecorded_disposition", disposition });
    return { status: 502, body: { error: "settlement_not_recorded", disposition, retry: true } };
  }

  const s = settlement as Record<string, unknown>;
  const reason = typeof s.reason === "string" ? s.reason : undefined;
  const reservationId = typeof s.reservation_id === "string" ? s.reservation_id : undefined;
  log({
    ...base,
    outcome: disposition === "refused" ? "refused" : "recorded",
    disposition,
    ...(reason !== undefined ? { reason } : {}),
    ...(reservationId !== undefined ? { reservation_id: reservationId } : {}),
  });
  // A refusal is final: a redelivery of the same bytes would be refused again.
  return {
    status: 200,
    body: { disposition, ...(reason !== undefined ? { reason } : {}), ...(reservationId !== undefined ? { reservation_id: reservationId } : {}) },
  };
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new Error("body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

/** The relay as a Node request listener. Validates the configuration up front. */
export function createSettlementRelayHandler(config: SettlementRelayConfig): RequestListener {
  settlementIngestUrl(config);

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let raw: Buffer;
    try {
      raw = await readBody(req);
    } catch {
      return send(res, 413, { error: "too large" });
    }
    const sig = req.headers["stripe-signature"];
    const out = await relayStripeEvent(raw, typeof sig === "string" ? sig : undefined, config);
    send(res, out.status, out.body);
  }

  return (req, res) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    let work: Promise<void>;
    if (req.method === "POST" && path === SETTLEMENT_RELAY_PATH) work = handle(req, res);
    else if (req.method === "GET" && path === "/healthz") work = Promise.resolve(send(res, 200, { ok: true }));
    else work = Promise.resolve(send(res, 404, { error: "not found" }));
    work.catch(() => {
      if (!res.headersSent) send(res, 500, { error: "internal error" });
    });
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const need = (name: string): string => {
    const v = process.env[name];
    if (!v) {
      console.error(`${name} is required`);
      process.exit(2);
    }
    return v;
  };
  const baseUrl = process.env.ATLASENT_BASE_URL;
  const config: SettlementRelayConfig = {
    webhookSecret: need("STRIPE_SETTLEMENT_WEBHOOK_SECRET"),
    apiKey: need("ATLASENT_INGEST_API_KEY"),
    connectorId: need("ATLASENT_SETTLEMENT_CONNECTOR_ID"),
    ...(baseUrl ? { baseUrl } : {}),
  };
  let handler: RequestListener;
  try {
    handler = createSettlementRelayHandler(config);
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(2);
  }
  const port = Number(process.env.PORT ?? 3002);
  createServer(handler).listen(port, () => console.log(`AtlaSent Stripe settlement relay listening on :${port}${SETTLEMENT_RELAY_PATH}`));
}

