/**
 * `atlasent.protect(...)` — the one-call, fail-closed execution-time
 * authorization boundary.
 *
 * ```ts
 * import atlasent from "@atlasent/sdk";
 *
 * const permit = await atlasent.protect({
 *   agent: "deploy-bot",
 *   action: "production.deploy",
 *   context: { commit, approver },
 * });
 * // …run the action. If we got here, AtlaSent authorized it
 * // end-to-end (evaluate + verifyPermit).
 * ```
 *
 * Unlike {@link AtlaSentClient.evaluate}, `protect` never returns a
 * denied decision. On deny, it throws {@link AtlaSentDeniedError};
 * on transport / auth / server failure it throws
 * {@link AtlaSentError}. The action cannot execute unless a valid
 * {@link Permit} is returned — this is the SDK's category boundary,
 * not a helper.
 *
 * `protectWithEvidence` is the same contract plus a signed
 * {@link DecisionReceipt} minted on the way out. Use it when you need
 * tamper-evident proof of authorization stored alongside the action
 * record (deploy logs, payment records, close workflows).
 */

import { AtlaSentClient, buildEvaluateBody } from "./client.js";
import type { DeployGateRequest, DeployGateResponse } from "./types.js";
import {
  AtlaSentDeniedError,
  AtlaSentError,
  BundleVerificationError,
  normalizePermitOutcome,
  type AtlaSentDecision,
} from "./errors.js";
import { getGlobalTrustRootManager } from "./trustRoot.js";
import { serverPayloadHash } from "./payloadHash.js";
import type { AtlaSentClientOptions, ConstraintTrace } from "./types.js";
import {
  buildDecisionReceiptPayload,
  buildWhyTrace,
  computeContextHash,
  signDecisionReceiptHmac,
} from "./evidenceEngine.js";
import type {
  DecisionReceipt,
  DecisionReceiptAlgorithm,
} from "./evidenceEngine.js";

/** Input to {@link protect}. Same shape as `EvaluateRequest`. */
export interface ProtectRequest {
  agent: string;
  action: string;
  context?: Record<string, unknown>;
  /**
   * SHA-256 digest of the exact payload this action will execute — the
   * arguments, the body, the diff: whatever "what is about to happen" means
   * for this action.
   *
   * Supplying it is what makes `PAYLOAD_MISMATCH` a real check. Without it,
   * the runtime binds the permit to its OWN hash of the whole evaluate
   * request, which your payload's digest can never equal, so nothing about
   * the payload actually constrains execution.
   *
   * Accepts bare 64-hex or a `sha256:`-prefixed digest; the prefix is
   * stripped, because the runtime silently DROPS a prefixed value rather than
   * rejecting it. Anything else THROWS — see
   * {@link normalizeExecutionPayloadHash} for why throwing is the fail-closed
   * choice.
   */
  executionPayloadHash?: string;
  /**
   * The actor's `actor_identity.v1` assertion. Presented unchanged at BOTH
   * boundaries: as `actor_identity` on evaluate (required there for the
   * mandatory change-control action types such as `production.deploy`) and
   * at verify (required when the action class is classified
   * `verified_actor`, atlasent-api#3915). The SDK never mints or inspects
   * it, and omitting it sends byte-identical requests to before.
   */
  actorIdentity?: Record<string, unknown>;
}

/**
 * The evaluate request protect() sends: the caller's request plus the
 * camelCase-to-wire fields at the TOP LEVEL (`execution_payload_hash`,
 * `actor_identity`), never inside `context`. With neither supplied it returns
 * the caller's object itself, so the request is byte-identical to before.
 * Spreads rather than mutates: `request` is the caller's object.
 */
function withWireBindings(
  request: ProtectRequest,
  executionPayloadHash: string | undefined,
): ProtectRequest & {
  execution_payload_hash?: string;
  actor_identity?: Record<string, unknown>;
} {
  if (executionPayloadHash === undefined && request.actorIdentity === undefined) {
    return request;
  }
  return {
    ...request,
    ...(executionPayloadHash !== undefined
      ? { execution_payload_hash: executionPayloadHash }
      : {}),
    ...(request.actorIdentity !== undefined
      ? { actor_identity: request.actorIdentity }
      : {}),
  };
}

/**
 * Normalize a caller-supplied execution payload digest, or throw.
 *
 * WHY THIS THROWS RATHER THAN DROPS. The runtime binds
 * `execution_hash_expected` only when the value matches `/^[0-9a-f]{64}$/i`
 * at the TOP LEVEL of the evaluate body. A `sha256:` prefix, or a value
 * nested under `context`, fails that test and is **dropped, not rejected**
 * on the ordinary-action path: allow, permit, 200, no error anywhere. The
 * caller believes the execution is bound to its payload and it is not.
 *
 * Two shipped clients each got one half of this wrong and neither could tell
 * — `atlasent-llm-integrations`' LangChain wrapper sent a `sha256:`-prefixed
 * digest nested under `context`, and its unit test asserted exactly that
 * shape and passed green for months. Sending something the runtime will
 * quietly discard is strictly worse than refusing at the client boundary, so
 * this refuses. Same fail-closed form as `normalizePayloadHash` in
 * `atlasent-mcp-server`'s `src/engine.ts`, deliberately rather than a second
 * invention.
 */
export function normalizeExecutionPayloadHash(value: string): string {
  const bare = value.startsWith("sha256:") ? value.slice("sha256:".length) : value;
  if (!/^[0-9a-fA-F]{64}$/.test(bare)) {
    throw new AtlaSentError(
      "executionPayloadHash must be a SHA-256 digest as 64 hex characters " +
        `(optionally "sha256:"-prefixed); got ${bare.length} character(s). ` +
        "The runtime silently DROPS a malformed digest rather than rejecting " +
        "it, so sending one would leave the execution unbound with no error.",
      { code: "bad_request" },
    );
  }
  return bare.toLowerCase();
}

/**
 * Success return from {@link protect}. The action is authorized
 * end-to-end — evaluation allowed AND the resulting permit verified.
 */
export interface Permit {
  /** Opaque permit / decision identifier. */
  permitId: string;
  /** Verification hash bound to the permit. */
  permitHash: string;
  /** Audit-trail entry associated with the decision (hash-chained). */
  auditHash: string;
  /** Human-readable reason from the policy engine. */
  reason: string;
  /** ISO 8601 timestamp of the verification. */
  timestamp: string;
  /** ISO-8601 expiration timestamp of the permit. null on pre-rollout servers. */
  permitExpiresAt: string | null;
}

/** Configuration for the process-wide singleton used by {@link protect}. */
export interface ConfigureOptions {
  /** Overrides `ATLASENT_API_KEY` env var. */
  apiKey?: string;
  /** Overrides the default `https://api.atlasent.io`. */
  baseUrl?: string;
  /** Per-request timeout in ms. */
  timeoutMs?: number;
  /** Inject a custom fetch (primarily for tests). */
  fetch?: typeof fetch;
  /** Override the retry policy. Pass `{ maxAttempts: 1 }` to disable retries. */
  retryPolicy?: import("./retry.js").RetryPolicy;
}

let sharedClient: AtlaSentClient | null = null;
let overrides: ConfigureOptions = {};

/**
 * Configure the singleton client used by {@link protect}. Optional —
 * if `ATLASENT_API_KEY` is set in the environment, `protect` works
 * without any configuration. Calling `configure` again replaces the
 * singleton; subsequent `protect` calls use the new settings.
 */
export function configure(options: ConfigureOptions): void {
  overrides = { ...overrides, ...options };
  sharedClient = null;
}

/**
 * Run the canonical Deploy Gate V1 helper using the process-wide client.
 * Defaults to action `production.deploy`; execution is allowed only after
 * server-side `/v1-evaluate` and `/v1-verify-permit` both pass.
 */
export async function deployGate(
  request: DeployGateRequest = {},
): Promise<DeployGateResponse> {
  return getClient().deployGate(request);
}

/** Reset the singleton. Exported for tests; not part of the public API. */
export function __resetSharedClientForTests(): void {
  sharedClient = null;
  overrides = {};
}

function getClient(): AtlaSentClient {
  if (sharedClient) return sharedClient;

  // Guard process.env access so this module is safe in browser and
  // edge-runtime environments where `process` is not defined as a global.
  const hasProcessEnv = typeof process !== "undefined" && !!process.env;
  const envApiKey = hasProcessEnv ? process.env.ATLASENT_API_KEY : undefined;
  const envBaseUrl = hasProcessEnv
    ? (process.env.ATLASENT_BASE_URL ?? process.env.ATLASENT_API_URL)
    : undefined;

  const apiKey = overrides.apiKey ?? envApiKey;
  if (!apiKey) {
    throw new AtlaSentError(
      "AtlaSent is not configured. Set ATLASENT_API_KEY in the environment, or call atlasent.configure({ apiKey }).",
      { code: "invalid_api_key" },
    );
  }
  const options: AtlaSentClientOptions = { apiKey };
  const baseUrl = overrides.baseUrl ?? envBaseUrl;
  if (baseUrl !== undefined) options.baseUrl = baseUrl;
  if (overrides.timeoutMs !== undefined)
    options.timeoutMs = overrides.timeoutMs;
  if (overrides.fetch !== undefined) options.fetch = overrides.fetch;
  if (overrides.retryPolicy !== undefined)
    options.retryPolicy = overrides.retryPolicy;
  sharedClient = new AtlaSentClient(options);
  return sharedClient;
}

// Mirrors the server-side ACTION_TYPE_RE in v1-evaluate/handler.ts.
const ACTION_TYPE_RE = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;

function wireDecisionToDenied(serverDecision: string): AtlaSentDecision {
  // Normalise to lowercase before matching — the decision field is now
  // always lowercase from evaluate(), but defensive lower-casing here
  // handles any edge case where an older code path sends uppercase.
  const lower = serverDecision.toLowerCase();
  if (lower === "hold" || lower === "escalate") return lower;
  return "deny";
}

// ── Execution-hash helpers ────────────────────────────────────────────────────

/**
 * Reproduce the binding the runtime falls back to when the caller supplied no
 * digest: `"sha256:" + hex` over the canonical form of the evaluate request
 * body, with the three fields `v1-evaluate` strips removed first.
 *
 * CORRECTED: this used to return BARE hex, and `#523` explicitly preserved
 * that on the no-caller-digest path ("behaviour is exactly as before"). That
 * path is the one that denies. `execution_evaluations.payload_hash` and the
 * permit's `execution_hash_expected` are written by the runtime's `hashPayload`,
 * which PREFIXES the scheme, and `/v1-verify-permit` folds case and normalizes
 * nothing else — so bare hex could never compare equal and every call without
 * a caller digest was a deterministic `PAYLOAD_MISMATCH`. The canonical BYTES
 * were always correct; `test/payload-hash-parity.test.ts` pins all ten vectors
 * against digests generated from the real server source, and only the prefix
 * was missing.
 *
 * `postedBody` must come from {@link buildEvaluateBody} — the body that is
 * actually sent — never a hand-written reconstruction of it. A field that
 * reaches the wire without reaching the hash yields a digest the server cannot
 * match. Not hypothetical: the Python SDK's mirror omitted `state_snapshot`,
 * so every `protect(state_snapshot=...)` call was a guaranteed mismatch on its
 * own, independently of the prefix.
 */
async function computeBoundPayloadHash(
  postedBody: Record<string, unknown>,
): Promise<string | undefined> {
  // v1-evaluate removes these three from the body before hashing it. Omitting
  // this strip survived the entire test suite until a test sent `explain`,
  // which is reachable through protect() — found by mutation testing, not by
  // reading.
  const {
    traceparent: _traceparent,
    shadow: _shadow,
    explain: _explain,
    ...core
  } = postedBody;

  try {
    return await serverPayloadHash(core);
  } catch {
    // Neither crypto.subtle nor node:crypto is available (a very old Node, a
    // restricted runtime). Omit the field rather than throw, preserving the
    // long-standing behaviour here: the server then requires it on a
    // production permit and denies with PAYLOAD_HASH_REQUIRED, which is
    // fail-closed. Warn, because a silently absent binding is the thing this
    // module exists to prevent.
    // eslint-disable-next-line no-console
    console.warn(
      "[atlasent] Could not compute the execution payload hash: neither " +
        "crypto.subtle nor node:crypto is available in this runtime. The " +
        "permit will not be verified against a payload binding, and a " +
        "production permit will be DENIED at verify.",
    );
    return undefined;
  }
}

function generateReceiptId(): string {
  if (
    typeof globalThis !== "undefined" &&
    typeof globalThis.crypto?.randomUUID === "function"
  ) {
    return globalThis.crypto.randomUUID();
  }
  return `rcpt_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * Authorize an action end-to-end. On allow, returns a verified
 * {@link Permit}. On anything else, throws:
 *
 * - {@link AtlaSentDeniedError} — policy denied, or the permit
 *   failed verification. Fail-closed: if this throws, the action
 *   MUST NOT proceed.
 * - {@link AtlaSentError} — transport, timeout, auth, rate-limit,
 *   or server error. Same fail-closed contract: do not proceed.
 */
export async function protect(request: ProtectRequest): Promise<Permit> {
  if (!ACTION_TYPE_RE.test(request.action)) {
    throw new AtlaSentError(
      `action must be in dot-notation format (e.g. "production.deploy"). Got: ${JSON.stringify(request.action)}`,
      { code: "bad_request" },
    );
  }
  // ADR-005 D3: fail-closed on expired trust snapshot. checkExpiry() also
  // emits the one-time half-life warning if >50% of validity window has elapsed.
  const trustMgr = getGlobalTrustRootManager({ disableRefresh: false });
  if (trustMgr.checkExpiry() === "expired") {
    const snap = trustMgr.getSnapshot();
    throw new BundleVerificationError({
      reason: "trust_snapshot_expired",
      snapshotValidUntil: snap.valid_until,
      snapshotFetchedAt: snap.issued_at,
    });
  }
  // Normalize BEFORE the evaluate call, so a malformed digest fails the
  // request outright instead of minting a permit the caller wrongly believes
  // is bound to its payload.
  const executionPayloadHash =
    request.executionPayloadHash !== undefined
      ? normalizeExecutionPayloadHash(request.executionPayloadHash)
      : undefined;

  const client = getClient();
  // Spread rather than mutate: `request` is the caller's object.
  // `executionPayloadHash` (camelCase, this SDK's surface) becomes
  // `execution_payload_hash` (the wire name) at TOP LEVEL — never inside
  // `context`, where the runtime never reads it. A caller that supplies no
  // digest sends a byte-identical request to before.
  //
  // Named rather than inlined so the fallback digest below can hash
  // buildEvaluateBody(evaluateRequest) — the same pure function on the same
  // input client.evaluate() gets, so it hashes the bytes that were posted
  // rather than a reconstruction that can drift from them.
  const evaluateRequest = withWireBindings(request, executionPayloadHash);
  const evaluation = await client.evaluate(evaluateRequest);

  // decision is now canonical lowercase: "allow" | "deny" | "hold" | "escalate"
  if (evaluation.decision !== "allow") {
    throw new AtlaSentDeniedError({
      decision: wireDecisionToDenied(evaluation.decision),
      evaluationId: evaluation.permitId,
      reason: evaluation.reason,
      auditHash: evaluation.auditHash,
    });
  }

  const environment = request.context?.environment as string | undefined;
  if (!environment) {
    throw new AtlaSentError(
      'context.environment is required. Pass the environment where this action executes (e.g. "production", "staging").',
      { code: "bad_request" },
    );
  }

  // What to present at the verify boundary.
  //
  // `v1-verify-permit` resolves ONE `callerPayloadHash` from the request —
  // `payload_hash` if present, else `execution_hash` as a back-compat alias —
  // and compares it against the permit's `boundPayloadHash`. So these two are
  // alternatives, never both, and presenting the WRONG one is a denial, not a
  // no-op.
  //
  // When the caller supplied a payload digest, that digest IS what the runtime
  // bound (`execution_hash_expected`), so it is the only value that can match.
  // Presenting the computed evaluate-payload hash instead would be a
  // DETERMINISTIC `PAYLOAD_MISMATCH` on every call — a hash of the request can
  // never equal a hash of the payload. That is not a hypothetical: it is the
  // defect the first draft of this change shipped, caught by reading
  // `v1-verify-permit/handler.ts`'s absence/comparison policy rather than by a
  // test, because no test here talks to a real runtime.
  //
  // With no caller digest, behaviour is exactly as before: hash the evaluate
  // payload so the server can validate integrity on consume.
  const execution_hash =
    executionPayloadHash ??
    (await computeBoundPayloadHash(buildEvaluateBody(evaluateRequest)));

  const verifyRequest: {
    permitId: string;
    agent: string;
    action: string;
    context?: Record<string, unknown>;
    environment: string;
    execution_hash?: string;
    actorIdentity?: Record<string, unknown>;
  } = {
    permitId: evaluation.permitId,
    agent: request.agent,
    action: request.action,
    environment,
    ...(execution_hash ? { execution_hash } : {}),
    ...(request.actorIdentity !== undefined
      ? { actorIdentity: request.actorIdentity }
      : {}),
  };
  if (request.context !== undefined) verifyRequest.context = request.context;
  const verification = await client.verifyPermit(verifyRequest);

  if (!verification.verified) {
    const outcome = normalizePermitOutcome(verification.outcome);
    throw new AtlaSentDeniedError({
      decision: "deny",
      evaluationId: evaluation.permitId,
      reason: `Permit failed verification (${verification.outcome})`,
      auditHash: evaluation.auditHash,
      ...(outcome !== undefined && { outcome }),
    });
  }

  return {
    permitId: evaluation.permitId,
    permitHash: verification.permitHash,
    auditHash: evaluation.auditHash,
    reason: evaluation.reason,
    timestamp: verification.timestamp,
    permitExpiresAt: verification.expiresAt ?? null,
  };
}

// ── Evidence-enhanced protect ─────────────────────────────────────────────────

/**
 * A verified {@link Permit} with an embedded signed {@link DecisionReceipt}.
 *
 * Returned by {@link protectWithEvidence}. Store `receipt` alongside
 * your action record (deploy logs, payment records, close workflows)
 * to give auditors a self-contained proof of authorization.
 */
export interface PermitWithEvidence extends Permit {
  /** Signed per-decision receipt. `algorithm: "none"` when no signing secret was supplied. */
  receipt: DecisionReceipt;
}

/** Options for {@link protectWithEvidence}. */
export interface ProtectWithEvidenceOptions {
  /**
   * HMAC-SHA256 signing secret. When provided, the receipt is signed
   * and can be verified offline with `verifyDecisionReceiptHmac`.
   * Recommend `process.env.ATLASENT_RECEIPT_SIGNING_SECRET`.
   */
  signingSecret?: string;
  /**
   * Registry key ID recorded on the receipt, paired with `signingSecret`.
   * Used for key rotation: store the ID alongside the receipt so
   * verifiers know which key to use.
   */
  signingKeyId?: string;
  /**
   * If you have already called `client.evaluatePreflight()` for this
   * request, pass `constraintTrace` here to populate
   * `receipt.why_trace` with the full stage-by-stage "why" trace.
   * When omitted, `why_trace` is `null` on the receipt.
   */
  constraintTrace?: ConstraintTrace | null;
}

/**
 * Authorize an action end-to-end and mint a signed {@link DecisionReceipt}.
 *
 * Same fail-closed contract as {@link protect} — throws
 * {@link AtlaSentDeniedError} on deny, {@link AtlaSentError} on
 * transport failure. The action MUST NOT proceed if this throws.
 *
 * On allow, returns the verified `Permit` plus a signed `DecisionReceipt`
 * that captures:
 * - The evaluation ID and decision
 * - Human-readable reasons
 * - Permit ID and hash
 * - Audit-trail hash (hash-chain link)
 * - SHA-256 of the evaluate context (tamper-evidence for the inputs)
 * - Optional "why" trace (pass `constraintTrace` from `evaluatePreflight`)
 *
 * ```ts
 * const { permit, receipt } = await protectWithEvidence(
 *   { agent: "deploy-bot", action: "production.deploy", context },
 *   {
 *     signingSecret: process.env.ATLASENT_RECEIPT_SIGNING_SECRET,
 *     signingKeyId: "key-v1",
 *   },
 * );
 * // Store alongside the deployment record.
 * await db.deployments.create({ commitSha, permit, receipt });
 * ```
 */
export async function protectWithEvidence(
  request: ProtectRequest,
  opts: ProtectWithEvidenceOptions = {},
): Promise<PermitWithEvidence> {
  if (!ACTION_TYPE_RE.test(request.action)) {
    throw new AtlaSentError(
      `action must be in dot-notation format (e.g. "production.deploy"). Got: ${JSON.stringify(request.action)}`,
      { code: "bad_request" },
    );
  }
  // Same normalize-before-evaluate contract as protect(). This entry point
  // previously ignored `executionPayloadHash` entirely: the camelCase field
  // never matches client.evaluate's snake_case allowlist, so the digest was
  // silently dropped and the permit was never bound to it — the exact
  // silent-drop defect the normalizer exists to prevent, in the sibling of
  // the function that got the fix.
  const executionPayloadHash =
    request.executionPayloadHash !== undefined
      ? normalizeExecutionPayloadHash(request.executionPayloadHash)
      : undefined;

  const client = getClient();

  // 1. Evaluate (same logic as protect()).
  const evaluateRequest = withWireBindings(request, executionPayloadHash);
  const evaluation = await client.evaluate(evaluateRequest);

  if (evaluation.decision !== "allow") {
    throw new AtlaSentDeniedError({
      decision: wireDecisionToDenied(evaluation.decision),
      evaluationId: evaluation.permitId,
      reason: evaluation.reason,
      auditHash: evaluation.auditHash,
    });
  }

  // 2. Extract environment, compute execution_hash, verify permit.
  const environment = request.context?.environment as string | undefined;
  if (!environment) {
    throw new AtlaSentError(
      'context.environment is required. Pass the environment where this action executes (e.g. "production", "staging").',
      { code: "bad_request" },
    );
  }

  const execution_hash =
    executionPayloadHash ??
    (await computeBoundPayloadHash(buildEvaluateBody(evaluateRequest)));

  const verifyRequest: {
    permitId: string;
    agent: string;
    action: string;
    context?: Record<string, unknown>;
    environment: string;
    execution_hash?: string;
    actorIdentity?: Record<string, unknown>;
  } = {
    permitId: evaluation.permitId,
    agent: request.agent,
    action: request.action,
    environment,
    ...(execution_hash ? { execution_hash } : {}),
    ...(request.actorIdentity !== undefined
      ? { actorIdentity: request.actorIdentity }
      : {}),
  };
  if (request.context !== undefined) verifyRequest.context = request.context;
  const verification = await client.verifyPermit(verifyRequest);

  if (!verification.verified) {
    const outcome = normalizePermitOutcome(verification.outcome);
    throw new AtlaSentDeniedError({
      decision: "deny",
      evaluationId: evaluation.permitId,
      reason: `Permit failed verification (${verification.outcome})`,
      auditHash: evaluation.auditHash,
      ...(outcome !== undefined && { outcome }),
    });
  }

  // 3. Build the receipt.
  const contextHash = await computeContextHash(request.context ?? {});

  const whyTrace = buildWhyTrace(
    "allow",
    evaluation.reasons,
    opts.constraintTrace ?? null,
  );

  const issuedAt = new Date().toISOString();
  const receiptId = generateReceiptId();
  const orgId = evaluation.permit?.orgId ?? "";

  const payload = buildDecisionReceiptPayload({
    receipt_id: receiptId,
    evaluation_id: evaluation.evaluationId,
    org_id: orgId,
    decision: "allow",
    action: request.action,
    actor: request.agent,
    resource_type:
      (request.context?.resource_type as string | undefined) ?? null,
    resource_id:
      (request.context?.resource_id as string | undefined) ?? null,
    reasons: evaluation.reasons,
    why_summary: whyTrace.summary,
    permit_id: evaluation.permitId,
    permit_hash: verification.permitHash,
    audit_hash: evaluation.auditHash,
    context_hash: contextHash,
    issued_at: issuedAt,
  });

  // 4. Sign if secret is provided.
  let signature: string | null = null;
  let algorithm: DecisionReceiptAlgorithm = "none";

  if (opts.signingSecret) {
    signature = await signDecisionReceiptHmac(payload, opts.signingSecret);
    algorithm = "hmac-sha256";
  }

  const receipt: DecisionReceipt = {
    receipt_id: receiptId,
    evaluation_id: evaluation.evaluationId,
    org_id: orgId,
    decision: "allow",
    action: request.action,
    actor: request.agent,
    resource_type:
      (request.context?.resource_type as string | undefined) ?? null,
    resource_id:
      (request.context?.resource_id as string | undefined) ?? null,
    reasons: evaluation.reasons,
    why_trace:
      opts.constraintTrace !== undefined ? whyTrace : null,
    permit_id: evaluation.permitId,
    permit_hash: verification.permitHash,
    audit_hash: evaluation.auditHash,
    context_hash: contextHash,
    issued_at: issuedAt,
    expires_at: null,
    algorithm,
    signature,
    signing_key_id: opts.signingKeyId ?? null,
    payload,
  };

  return {
    permitId: evaluation.permitId,
    permitHash: verification.permitHash,
    auditHash: evaluation.auditHash,
    reason: evaluation.reason,
    timestamp: verification.timestamp,
    permitExpiresAt: verification.expiresAt ?? null,
    receipt,
  };
}
