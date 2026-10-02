/**
 * V2 Wave-A endpoints (V2-D3, V2-D4, V2-D8) — additive on top of v1.
 *
 * Three additional methods on top of the v1 {@link AtlaSentClient}
 * surface that target the new wire endpoints landed in `atlasent-api`
 * PRs #742 (batch), #745 (stream), and #746 (graphql).
 *
 * The v1 substrate is frozen (post-GA 2026-05-17) — this module is
 * purely additive. Existing 1.x methods (`protect`, `requirePermit`,
 * `evaluate`, …) are untouched.
 *
 * ## Closed-by-default discipline
 *
 * Each tenant gates the new endpoints behind `v2_batch`,
 * `v2_streaming`, and `v2_graphql` flags. When the flag is off the
 * API returns HTTP 404, surfaced here as {@link FeatureNotEnabledError}
 * so callers can deterministically fall back (typically to a per-item
 * `/v1-evaluate` loop). The SDK never silently falls back — that would
 * change billing and audit semantics.
 */

import { functionRegionHeaders } from "./functionRegion.js";
import { AtlaSentError, type AtlaSentErrorInit } from "./errors.js";

// ── Constants ────────────────────────────────────────────────────────

export const V2_BATCH_PATH = "/v1/evaluate/batch";
export const V2_STREAM_PATH = "/v1/evaluate/stream";
export const V2_GRAPHQL_PATH = "/v1/graphql";

/** Maximum items per batch (mirrors the server-side cap, V2-D3). */
export const V2_MAX_BATCH_ITEMS = 100;
/** Maximum request body size (mirrors the server-side 1MB cap). */
export const V2_MAX_BODY_BYTES = 1_000_000;
/** GraphQL document depth cap (V2-D2). */
export const V2_GRAPHQL_MAX_DEPTH = 8;

// ── Errors ───────────────────────────────────────────────────────────

/**
 * Identifier of the tenant flag gating a V2 endpoint.
 */
export type V2Feature = "batch" | "streaming" | "graphql";

/**
 * Initialization options for {@link FeatureNotEnabledError}.
 */
export interface FeatureNotEnabledErrorInit {
  feature: V2Feature;
  endpoint: string;
  requestId?: string;
}

/**
 * Thrown when a V2 endpoint returns 404 because the tenant feature
 * flag is off.
 *
 * The three V2 endpoints (`/v1/evaluate/batch`, `/v1/evaluate/stream`,
 * `/v1/graphql`) are close-by-default per tenant. When the
 * corresponding flag is unset, the API returns HTTP 404; the SDK
 * surfaces that as this distinct error so the caller can
 * deterministically fall back to the v1 per-item loop.
 *
 * Subclass of {@link AtlaSentError} so `instanceof AtlaSentError`
 * catches it alongside the SDK's other typed errors.
 */
export class FeatureNotEnabledError extends AtlaSentError {
  override name: string = "FeatureNotEnabledError";

  /** Which tenant flag is gating the endpoint. */
  readonly feature: V2Feature;
  /** The wire path the SDK attempted (for diagnostics). */
  readonly endpoint: string;

  constructor(init: FeatureNotEnabledErrorInit) {
    const message =
      `AtlaSent V2 feature '${init.feature}' is not enabled for this tenant ` +
      `(POST ${init.endpoint} returned 404). Enable the v2_${init.feature} ` +
      `flag or fall back to the v1 per-item /v1-evaluate loop.`;
    // `feature_disabled` (not `forbidden`): the request was not denied
    // on authorization grounds — the tenant lacks the v2_<feature> flag.
    // Callers branching on `err.code === "forbidden"` would otherwise
    // conflate this with real 403 auth failures.
    const errInit: AtlaSentErrorInit = { status: 404, code: "feature_disabled" };
    if (init.requestId !== undefined) errInit.requestId = init.requestId;
    super(message, errInit);
    this.feature = init.feature;
    this.endpoint = init.endpoint;
  }
}

// ── Response / event shapes ────────────────────────────────────────────────

/**
 * One element of an {@link EvaluateBatchResponse.items} list.
 *
 * Preserves input order — `items[i]` corresponds to `request.items[i]`.
 * On a per-item RPC failure the server returns `decision: undefined`
 * and populates `errorCode` / `errorMessage` instead.
 */
export interface EvaluateBatchItem {
  index: number;
  decision?: string;
  decisionId?: string;
  permitToken?: string;
  reason?: string;
  errorCode?: string;
  errorMessage?: string;
}

/** Response shape for `POST /v1/evaluate/batch`. */
export interface EvaluateBatchResponse {
  batchId: string;
  items: ReadonlyArray<EvaluateBatchItem>;
  partial: boolean;
}

/** Request payload for {@link evaluateMany} and {@link authorizeStream}. */
export interface EvaluateManyRequest {
  items: ReadonlyArray<Record<string, unknown>>;
  batchId?: string;
}

/** `event: decision` frame surfaced via the `onDecision` callback. */
export interface StreamDecisionFrame {
  index: number;
  decision: string;
  decisionId?: string;
  permitToken?: string;
  reason?: string;
}

/** `event: error` frame surfaced via the `onError` callback. */
export interface StreamErrorFrame {
  index: number;
  errorCode: string;
  message: string;
}

/** Terminal `event: complete` payload returned by {@link authorizeStream}. */
export interface StreamComplete {
  batchId: string;
  count: number;
  partial: boolean;
}

/** GraphQL request body. */
export interface GraphQLRequest {
  query: string;
  variables?: Record<string, unknown>;
  operationName?: string;
}

/**
 * GraphQL response. Resolver errors land on `errors`; the SDK does
 * not throw on them — the caller branches.
 */
export interface GraphQLResponse<T = unknown> {
  data: T | null;
  errors?: ReadonlyArray<Record<string, unknown>>;
}

// ── Minimal client surface this module needs ──────────────────────────────────────

/**
 * The minimal subset of an {@link AtlaSentClient}-like object this
 * module needs: a `fetch`-compatible HTTP function and a base URL.
 *
 * Passed explicitly so the v2 module never reaches into v1 internals
 * (and so callers can plug in a custom fetch for testing / edge
 * runtimes / Node fetch wrappers).
 */
export interface V2Transport {
  /** Base URL (no trailing slash), e.g. `https://api.atlasent.io`. */
  baseUrl: string;
  /** Bearer API key (without the `Bearer ` prefix). */
  apiKey: string;
  /** A `fetch`-like function. Defaults to global `fetch` if omitted. */
  fetch?: typeof fetch;
}

// ── UUID validation ──────────────────────────────────────────────────────────

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function assertValidBatchId(batchId: string | undefined): void {
  if (batchId === undefined) return;
  if (typeof batchId !== "string" || !UUID_RE.test(batchId)) {
    throw new TypeError(`batchId must be a valid UUID: ${String(batchId)}`);
  }
}

function assertItemsShape(items: ReadonlyArray<unknown>): void {
  if (!Array.isArray(items) || items.length === 0) {
    throw new TypeError("items must be a non-empty array");
  }
  if (items.length > V2_MAX_BATCH_ITEMS) {
    throw new TypeError(
      `items length ${items.length} exceeds maximum of ${V2_MAX_BATCH_ITEMS}`,
    );
  }
}

function assertBodyWithinCap(raw: string): void {
  // UTF-8 byte length, not character length.
  const bytes = new TextEncoder().encode(raw).length;
  if (bytes > V2_MAX_BODY_BYTES) {
    throw new TypeError(
      `request body ${bytes} bytes exceeds maximum of ${V2_MAX_BODY_BYTES}`,
    );
  }
}

function commonHeaders(apiKey: string, url: string): Record<string, string> {
  return {
    "Content-Type": "application/json",
    Accept: "application/json",
    Authorization: `Bearer ${apiKey}`,
    ...functionRegionHeaders(url),
  };
}

function pickFetch(t: V2Transport): typeof fetch {
  if (t.fetch !== undefined) return t.fetch;
  if (typeof fetch !== "undefined") return fetch;
  throw new Error(
    "v2: no fetch implementation available (set transport.fetch or run on Node ≥ 18)",
  );
}

// ── evaluateMany ──────────────────────────────────────────────────────────

/**
 * `POST /v1/evaluate/batch` — V2-D3.
 *
 * One round-trip for up to {@link V2_MAX_BATCH_ITEMS} evaluate items.
 * Items are returned in input order — `response.items[i].index === i`.
 *
 * @throws {FeatureNotEnabledError} When the tenant `v2_batch` flag is off (404).
 * @throws {AtlaSentError} For any other transport / HTTP failure.
 * @throws {TypeError} When `items` is empty, exceeds the cap, or
 *   `batchId` is not a valid UUID.
 */
export async function evaluateMany(
  transport: V2Transport,
  req: EvaluateManyRequest,
): Promise<EvaluateBatchResponse> {
  assertItemsShape(req.items);
  assertValidBatchId(req.batchId);

  const body: Record<string, unknown> = { items: req.items };
  if (req.batchId !== undefined) body["batch_id"] = req.batchId;
  const raw = JSON.stringify(body);
  assertBodyWithinCap(raw);

  const url = `${transport.baseUrl}${V2_BATCH_PATH}`;
  const fetchImpl = pickFetch(transport);
  const response = await fetchImpl(url, {
    method: "POST",
    headers: commonHeaders(transport.apiKey, url),
    body: raw,
  });

  const requestId = response.headers.get("X-Request-ID") ?? undefined;
  if (response.status === 404) {
    const init: FeatureNotEnabledErrorInit = {
      feature: "batch",
      endpoint: V2_BATCH_PATH,
    };
    if (requestId !== undefined) init.requestId = requestId;
    throw new FeatureNotEnabledError(init);
  }
  if (!response.ok) {
    throwHttpError(V2_BATCH_PATH, response.status, requestId);
  }

  const parsed = await safeJson(response, V2_BATCH_PATH, requestId);
  return parseBatchResponse(parsed);
}

function parseBatchResponse(data: unknown): EvaluateBatchResponse {
  const root = (data ?? {}) as Record<string, unknown>;
  const rawItems = (root["items"] ?? []) as ReadonlyArray<
    Record<string, unknown>
  >;
  const items: EvaluateBatchItem[] = rawItems.map((it) => {
    const out: EvaluateBatchItem = {
      index: typeof it["index"] === "number" ? (it["index"] as number) : -1,
    };
    const decision = it["decision"];
    if (typeof decision === "string") out.decision = decision;
    const decisionId = it["decision_id"];
    if (typeof decisionId === "string") out.decisionId = decisionId;
    const permitToken = it["permit_token"];
    if (typeof permitToken === "string") out.permitToken = permitToken;
    const reason = it["reason"];
    if (typeof reason === "string") out.reason = reason;
    const errorCode = it["error_code"];
    if (typeof errorCode === "string") out.errorCode = errorCode;
    const errorMessage = it["error_message"];
    if (typeof errorMessage === "string") out.errorMessage = errorMessage;
    return out;
  });
  const batchId = root["batch_id"];
  return {
    batchId: typeof batchId === "string" ? batchId : "",
    items,
    partial: Boolean(root["partial"]),
  };
}

// ── authorizeStream ──────────────────────────────────────────────────────────

/**
 * Callbacks consumed by {@link authorizeStream}.
 */
export interface AuthorizeStreamHandlers {
  onDecision?: (frame: StreamDecisionFrame) => void;
  onError?: (frame: StreamErrorFrame) => void;
}

/**
 * `POST /v1/evaluate/stream` — V2-D4.
 *
 * Streams `event: decision` frames in input order. Per-item RPC
 * failures arrive as `event: error` frames and do not tear down the
 * stream (V2-D7 async semantics). Resolves with the terminal
 * `event: complete` payload.
 *
 * @throws {FeatureNotEnabledError} When the tenant `v2_streaming` flag is off.
 * @throws {AtlaSentError} For transport failures, including the stream
 *   closing without a `complete` frame.
 */
export async function authorizeStream(
  transport: V2Transport,
  req: EvaluateManyRequest,
  handlers: AuthorizeStreamHandlers = {},
): Promise<StreamComplete> {
  assertItemsShape(req.items);
  assertValidBatchId(req.batchId);

  const body: Record<string, unknown> = { items: req.items };
  if (req.batchId !== undefined) body["batch_id"] = req.batchId;
  const raw = JSON.stringify(body);
  assertBodyWithinCap(raw);

  const url = `${transport.baseUrl}${V2_STREAM_PATH}`;
  const fetchImpl = pickFetch(transport);
  const response = await fetchImpl(url, {
    method: "POST",
    headers: {
      ...commonHeaders(transport.apiKey, url),
      Accept: "text/event-stream",
    },
    body: raw,
  });

  const requestId = response.headers.get("X-Request-ID") ?? undefined;
  if (response.status === 404) {
    const init: FeatureNotEnabledErrorInit = {
      feature: "streaming",
      endpoint: V2_STREAM_PATH,
    };
    if (requestId !== undefined) init.requestId = requestId;
    throw new FeatureNotEnabledError(init);
  }
  if (!response.ok) {
    throwHttpError(V2_STREAM_PATH, response.status, requestId);
  }
  if (response.body === null) {
    throw new AtlaSentError(
      `POST ${V2_STREAM_PATH} returned no response body`,
      { code: "bad_response", status: response.status },
    );
  }

  const complete = await consumeSseStream(response.body, handlers);
  if (complete === null) {
    throw new AtlaSentError(
      "authorizeStream: stream closed without a `complete` event",
      { code: "bad_response" },
    );
  }
  return complete;
}

async function consumeSseStream(
  body: ReadableStream<Uint8Array>,
  handlers: AuthorizeStreamHandlers,
): Promise<StreamComplete | null> {
  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buffer = "";
  let eventName: string | undefined = undefined;
  let complete: StreamComplete | null = null;

  // eslint-disable-next-line no-constant-condition
  while (true) {
    const { value, done } = await reader.read();
    if (value !== undefined) {
      buffer += decoder.decode(value, { stream: !done });
    }
    if (done) {
      buffer += decoder.decode();
    }

    // Process complete lines (separator: \n; tolerate \r\n).
    let nl: number;
    while ((nl = buffer.indexOf("\n")) !== -1) {
      let line = buffer.slice(0, nl);
      buffer = buffer.slice(nl + 1);
      if (line.endsWith("\r")) line = line.slice(0, -1);

      if (line === "") {
        eventName = undefined;
        continue;
      }
      if (line.startsWith(":")) continue; // keep-alive heartbeat
      if (line.startsWith("event:")) {
        eventName = line.slice("event:".length).trim();
        continue;
      }
      if (!line.startsWith("data:")) continue;
      const dataText = line.slice("data:".length).trim();
      let payload: unknown;
      try {
        payload = JSON.parse(dataText);
      } catch {
        continue;
      }
      if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
        continue;
      }
      const p = payload as Record<string, unknown>;
      if (eventName === "decision" && handlers.onDecision !== undefined) {
        const dIndex = p["index"];
        const dDecision = p["decision"];
        const frame: StreamDecisionFrame = {
          index: typeof dIndex === "number" ? dIndex : -1,
          decision: typeof dDecision === "string" ? dDecision : "",
        };
        const dId = p["decision_id"];
        if (typeof dId === "string") frame.decisionId = dId;
        const pt = p["permit_token"];
        if (typeof pt === "string") frame.permitToken = pt;
        const r = p["reason"];
        if (typeof r === "string") frame.reason = r;
        handlers.onDecision(frame);
      } else if (eventName === "error" && handlers.onError !== undefined) {
        const eIndex = p["index"];
        const eCode = p["error_code"];
        const eMsg = p["message"];
        handlers.onError({
          index: typeof eIndex === "number" ? eIndex : -1,
          errorCode: typeof eCode === "string" ? eCode : "",
          message: typeof eMsg === "string" ? eMsg : "",
        });
      } else if (eventName === "complete") {
        const cBatchId = p["batch_id"];
        const cCount = p["count"];
        complete = {
          batchId: typeof cBatchId === "string" ? cBatchId : "",
          count: typeof cCount === "number" ? cCount : 0,
          partial: Boolean(p["partial"]),
        };
        try {
          await reader.cancel();
        } catch {
          // best-effort cancel
        }
        return complete;
      }
    }

    if (done) break;
  }

  return complete;
}

// ── graphql ───────────────────────────────────────────────────────────

/**
 * `POST /v1/graphql` — V2-D2 + V2-D8.
 *
 * Bearer-only auth (no query-param). Wave A schema is read-only
 * (`recentEvaluations(limit)` + `activeBundle`). Server enforces the
 * V2-D8 OR-gate (`audit:read` OR `policy:read`) at request layer and
 * a per-resolver AND-gate at field resolution time.
 *
 * Resolver-level errors surface on `response.errors` — the SDK does
 * not throw on them so callers can inspect partial data.
 *
 * @throws {FeatureNotEnabledError} When the tenant `v2_graphql` flag is off.
 * @throws {AtlaSentError} For transport / HTTP failures.
 * @throws {TypeError} When `query` is empty or the body exceeds the 1MB cap.
 */
export async function graphql<T = unknown>(
  transport: V2Transport,
  req: GraphQLRequest,
): Promise<GraphQLResponse<T>> {
  if (typeof req.query !== "string" || req.query.trim() === "") {
    throw new TypeError("query must be a non-empty string");
  }
  const body: Record<string, unknown> = { query: req.query };
  if (req.variables !== undefined) body["variables"] = req.variables;
  if (req.operationName !== undefined)
    body["operationName"] = req.operationName;

  const raw = JSON.stringify(body);
  assertBodyWithinCap(raw);

  const url = `${transport.baseUrl}${V2_GRAPHQL_PATH}`;
  const fetchImpl = pickFetch(transport);
  const response = await fetchImpl(url, {
    method: "POST",
    headers: commonHeaders(transport.apiKey, url),
    body: raw,
  });
  const requestId = response.headers.get("X-Request-ID") ?? undefined;
  if (response.status === 404) {
    const init: FeatureNotEnabledErrorInit = {
      feature: "graphql",
      endpoint: V2_GRAPHQL_PATH,
    };
    if (requestId !== undefined) init.requestId = requestId;
    throw new FeatureNotEnabledError(init);
  }
  if (!response.ok) {
    throwHttpError(V2_GRAPHQL_PATH, response.status, requestId);
  }

  const parsed = (await safeJson(response, V2_GRAPHQL_PATH, requestId)) as
    | Record<string, unknown>
    | null;
  const root = parsed ?? {};
  const out: GraphQLResponse<T> = {
    data: (root["data"] ?? null) as T | null,
  };
  const errs = root["errors"];
  if (Array.isArray(errs) && errs.length > 0) {
    out.errors = errs as ReadonlyArray<Record<string, unknown>>;
  }
  return out;
}

// ── helpers ───────────────────────────────────────────────────────────

function throwHttpError(
  path: string,
  status: number,
  requestId: string | undefined,
): never {
  const errInit: AtlaSentErrorInit = {
    status,
    code: status >= 500 ? "server_error" : "bad_request",
  };
  if (requestId !== undefined) errInit.requestId = requestId;
  throw new AtlaSentError(`POST ${path} returned ${status}`, errInit);
}

async function safeJson(
  response: Response,
  path: string,
  requestId: string | undefined,
): Promise<unknown> {
  try {
    return await response.json();
  } catch (cause) {
    const errInit: AtlaSentErrorInit = {
      status: response.status,
      code: "bad_response",
      cause,
    };
    if (requestId !== undefined) errInit.requestId = requestId;
    throw new AtlaSentError(`${path}: malformed JSON response`, errInit);
  }
}
