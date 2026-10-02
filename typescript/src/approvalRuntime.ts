/**
 * Approval/Override Runtime — fail-closed bridge between policy `hold`/`escalate`
 * outcomes and human approval.
 *
 * `protectOrEscalate()` — like `protect()` but handles hold/escalate by:
 *   1. Creating an HITL escalation via POST /v1/hitl
 *   2. Polling until approved, rejected, or timed out
 *   3. Returning an `ApprovalPermit` on approval; throwing on rejection/timeout
 *
 * `createEscalation()` — create an HITL escalation request (lower-level)
 * `waitForEscalationApproval()` — poll until the escalation resolves
 * `requestOverride()` — request a post-hoc override for a denied evaluation
 * `configureApprovalRuntime()` — set API key / base URL once
 */

import { functionRegionHeaders } from "./functionRegion.js";
import { AtlaSentDeniedError, AtlaSentError } from "./errors.js";
import type {
  HitlCreateRequest,
  HitlEscalation,
  HitlFallbackDecision,
  HitlQuorumTier,
} from "./hitl.js";
import type { CreateOverrideRequest, OverrideV1 } from "./overrides.js";
import { protect, type Permit, type ProtectRequest } from "./protect.js";

// ── Module-level configuration singleton ────────────────────────────────────

export interface ApprovalRuntimeConfig {
  apiKey?: string;
  baseUrl?: string;
  /** Per-request HTTP timeout in ms. Default 30_000. */
  timeoutMs?: number;
}

let _runtimeConfig: ApprovalRuntimeConfig = {};

/**
 * Configure the Approval Runtime singleton. Optional — if `ATLASENT_API_KEY` is
 * set in the environment, the runtime works without configuration. Calling this
 * again merges into the existing config.
 */
export function configureApprovalRuntime(config: ApprovalRuntimeConfig): void {
  _runtimeConfig = { ..._runtimeConfig, ...config };
}

function resolveConfig(overrides?: { apiKey?: string; baseUrl?: string }): {
  apiKey: string;
  baseUrl: string;
  requestTimeoutMs: number;
} {
  const apiKey =
    overrides?.apiKey ??
    _runtimeConfig.apiKey ??
    (typeof process !== "undefined" && process.env
      ? process.env["ATLASENT_API_KEY"]
      : undefined);

  if (!apiKey) {
    throw new AtlaSentError(
      "ApprovalRuntime: no API key configured. Set ATLASENT_API_KEY or call configureApprovalRuntime({ apiKey }).",
      { code: "invalid_api_key" },
    );
  }

  return {
    apiKey,
    baseUrl:
      overrides?.baseUrl ??
      _runtimeConfig.baseUrl ??
      "https://api.atlasent.io",
    requestTimeoutMs: _runtimeConfig.timeoutMs ?? 30_000,
  };
}

// ── Thin HTTP helpers (avoids importing the full AtlaSentClient) ─────────────

interface ResolvedConfig {
  apiKey: string;
  baseUrl: string;
  requestTimeoutMs: number;
}

async function apiPost<T>(
  path: string,
  body: unknown,
  cfg: ResolvedConfig,
): Promise<T> {
  const url = `${cfg.baseUrl}${path}`;
  let resp: Response;
  try {
    resp = await fetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${cfg.apiKey}`,
        ...functionRegionHeaders(url),
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(cfg.requestTimeoutMs),
    });
  } catch (err) {
    throw new AtlaSentError(
      `ApprovalRuntime: network error calling ${path}`,
      { code: "network", cause: err },
    );
  }

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    const code =
      resp.status === 401
        ? "invalid_api_key"
        : resp.status === 403
          ? "forbidden"
          : resp.status === 429
            ? "rate_limited"
            : "server_error";
    throw new AtlaSentError(
      `ApprovalRuntime: API error ${resp.status} at ${path}: ${text.slice(0, 200)}`,
      { code, status: resp.status },
    );
  }
  return resp.json() as Promise<T>;
}

async function apiGet<T>(path: string, cfg: ResolvedConfig): Promise<T> {
  const url = `${cfg.baseUrl}${path}`;
  let resp: Response;
  try {
    resp = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${cfg.apiKey}`,
        ...functionRegionHeaders(url),
      },
      signal: AbortSignal.timeout(cfg.requestTimeoutMs),
    });
  } catch (err) {
    throw new AtlaSentError(
      `ApprovalRuntime: network error calling ${path}`,
      { code: "network", cause: err },
    );
  }

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    const code =
      resp.status === 401
        ? "invalid_api_key"
        : resp.status === 403
          ? "forbidden"
          : resp.status === 429
            ? "rate_limited"
            : "server_error";
    throw new AtlaSentError(
      `ApprovalRuntime: API error ${resp.status} at ${path}: ${text.slice(0, 200)}`,
      { code, status: resp.status },
    );
  }
  return resp.json() as Promise<T>;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── Core types ────────────────────────────────────────────────────────────────

/** Opaque handle returned when an escalation is created. */
export interface EscalationHandle {
  readonly escalationId: string;
  readonly createdAt: string;
  readonly timeoutAt: string | null;
  readonly assignedToRole: string | null;
}

/** Terminal resolution status of an escalation. */
export type ApprovalStatus = "approved" | "rejected" | "timed_out";

/** Full outcome returned when an escalation resolves. */
export interface EscalationOutcome {
  readonly status: ApprovalStatus;
  readonly escalation: HitlEscalation;
  readonly resolvedBy: string | null;
  readonly resolutionNote: string | null;
  readonly resolvedAt: string | null;
}

/**
 * Thrown by `protectOrEscalate` / `waitForEscalationApproval` when the
 * human reviewer rejects the escalation.
 */
export class EscalationDeniedError extends Error {
  override readonly name = "EscalationDeniedError" as const;
  readonly escalationId: string;
  readonly outcome: EscalationOutcome;

  constructor(outcome: EscalationOutcome) {
    super(
      `Escalation ${outcome.escalation.id} was rejected` +
        (outcome.resolutionNote ? `: ${outcome.resolutionNote}` : ""),
    );
    this.escalationId = outcome.escalation.id;
    this.outcome = outcome;
  }
}

/**
 * Thrown by `protectOrEscalate` / `waitForEscalationApproval` when the
 * client-side wait window expires before the escalation resolves.
 */
export class EscalationTimeoutError extends Error {
  override readonly name = "EscalationTimeoutError" as const;
  readonly escalationId: string;
  readonly outcome: EscalationOutcome;

  constructor(outcome: EscalationOutcome) {
    super(
      `Escalation ${outcome.escalation.id} timed out waiting for approval`,
    );
    this.escalationId = outcome.escalation.id;
    this.outcome = outcome;
  }
}

// ── createEscalation ──────────────────────────────────────────────────────────

/**
 * Options for creating an HITL escalation. Extends `HitlCreateRequest` with
 * API-key and base-URL overrides for per-call credential injection.
 */
export interface CreateEscalationOptions extends Partial<HitlCreateRequest> {
  apiKey?: string;
  baseUrl?: string;
}

/**
 * Create an HITL escalation via POST /v1/hitl.
 *
 * The escalation is placed in `pending` status; a reviewer must approve or
 * reject it before the original action can proceed. Use
 * `waitForEscalationApproval()` to poll until the escalation resolves.
 */
export async function createEscalation(
  opts: CreateEscalationOptions,
): Promise<EscalationHandle> {
  const { apiKey, baseUrl, ...hitlBody } = opts;
  const cfg = resolveConfig({
    ...(apiKey !== undefined ? { apiKey } : {}),
    ...(baseUrl !== undefined ? { baseUrl } : {}),
  });

  const body: HitlCreateRequest = {
    agent_id: hitlBody.agent_id ?? "unknown",
    escalation_reason:
      hitlBody.escalation_reason ?? "Policy hold — awaiting human approval",
    ...hitlBody,
  };

  const escalation = await apiPost<HitlEscalation>("/v1/hitl", body, cfg);
  return {
    escalationId: escalation.id,
    createdAt: escalation.created_at,
    timeoutAt: escalation.timeout_at ?? null,
    assignedToRole: escalation.assigned_to_role ?? null,
  };
}

// ── waitForEscalationApproval ─────────────────────────────────────────────────

export interface WaitForApprovalOptions {
  escalationId: string;
  /** Max milliseconds to wait for a human to respond. Default 600_000 (10 min). */
  waitMs?: number;
  /** How often to poll the API. Default 5000ms. Minimum 1000ms. */
  pollIntervalMs?: number;
  apiKey?: string;
  baseUrl?: string;
}

/**
 * Poll GET /v1/escalations/:id until the escalation reaches a terminal status
 * (`approved`, `auto_approved`, `rejected`, or `timed_out`).
 *
 * Returns the resolved outcome regardless of approval/rejection — the caller
 * decides whether to throw. Use `protectOrEscalate()` for the opinionated flow.
 */
export async function waitForEscalationApproval(
  opts: WaitForApprovalOptions,
): Promise<EscalationOutcome> {
  const cfg = resolveConfig({
    ...(opts.apiKey !== undefined ? { apiKey: opts.apiKey } : {}),
    ...(opts.baseUrl !== undefined ? { baseUrl: opts.baseUrl } : {}),
  });
  const waitMs = opts.waitMs ?? 600_000;
  const pollIntervalMs = Math.max(opts.pollIntervalMs ?? 5_000, 1_000);
  const deadline = Date.now() + waitMs;

  const toOutcome = (escalation: HitlEscalation): EscalationOutcome | null => {
    const terminal =
      escalation.status === "approved" ||
      escalation.status === "rejected" ||
      escalation.status === "auto_approved" ||
      escalation.status === "timed_out";

    if (!terminal) return null;

    const status: ApprovalStatus =
      escalation.status === "approved" || escalation.status === "auto_approved"
        ? "approved"
        : escalation.status === "timed_out"
          ? "timed_out"
          : "rejected";

    return {
      status,
      escalation,
      resolvedBy: escalation.resolved_by ?? null,
      resolutionNote: escalation.resolution_note ?? null,
      resolvedAt: escalation.resolved_at ?? null,
    };
  };

  while (Date.now() < deadline) {
    const escalation = await apiGet<HitlEscalation>(
      `/v1/escalations/${opts.escalationId}`,
      cfg,
    );
    const outcome = toOutcome(escalation);
    if (outcome) return outcome;

    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    await sleep(Math.min(pollIntervalMs, remaining));
  }

  // Final fetch at deadline
  const escalation = await apiGet<HitlEscalation>(
    `/v1/escalations/${opts.escalationId}`,
    cfg,
  );
  const outcome = toOutcome(escalation);
  if (outcome) return outcome;

  return {
    status: "timed_out",
    escalation,
    resolvedBy: null,
    resolutionNote: "Client-side wait timeout elapsed",
    resolvedAt: null,
  };
}

// ── protectOrEscalate ─────────────────────────────────────────────────────────

/**
 * A verified Permit granted via human approval of an HITL escalation.
 * Extends {@link Permit} with escalation provenance fields.
 *
 * `approvalBasis: "direct_policy"` — action was allowed directly by policy;
 * no escalation was created.
 *
 * `approvalBasis: "human_approval"` — the policy returned `hold`/`escalate`;
 * a human reviewer approved the escalation.
 *
 * Guards and enforcement adapters should treat both as equivalent authorization
 * proof; auditors can distinguish them via `escalationId`.
 */
export interface ApprovalPermit extends Permit {
  /**
   * The HITL escalation ID that authorized this action. Empty string when
   * the action was directly allowed by policy (no escalation needed).
   */
  readonly escalationId: string;
  /** Identity of the reviewer who approved, or `null` for `auto_approved`. */
  readonly resolvedBy: string | null;
  readonly resolutionNote: string | null;
  readonly resolvedAt: string;
  readonly approvalBasis: "direct_policy" | "human_approval";
}

export interface ProtectOrEscalateOptions {
  /** Agent ID recorded on the escalation. Defaults to `request.agent`. */
  agentId?: string;
  /** Human-readable reason surfaced in the reviewer's queue. */
  escalationReason?: string;
  /** The proposed action payload shown to reviewers. Defaults to `request.context`. */
  proposedAction?: Record<string, unknown>;
  riskScore?: number;
  assignedToRole?: string;
  quorumRequired?: HitlQuorumTier;
  fallbackDecision?: HitlFallbackDecision;
  /** ISO-8601 — when the escalation should auto-resolve per server policy. */
  timeoutAt?: string;
  metadata?: Record<string, unknown>;
  /** Max ms to wait for a human decision. Default 600_000 (10 min). */
  waitMs?: number;
  /** How often to poll. Default 5000ms. */
  pollIntervalMs?: number;
  apiKey?: string;
  baseUrl?: string;
  /** Called with the EscalationHandle immediately after it is created. */
  onEscalationCreated?: (handle: EscalationHandle) => void;
}

/**
 * Authorize an action end-to-end, automatically escalating to human review
 * when the policy returns `hold` or `escalate`.
 *
 * **Directly allowed** → returns `ApprovalPermit` with
 *   `approvalBasis: "direct_policy"` (same semantics as `protect()`).
 *
 * **Hold / escalate** → creates an HITL escalation, polls for a human
 *   decision, and returns `ApprovalPermit` with
 *   `approvalBasis: "human_approval"` on approval.
 *
 * **Throws**:
 * - {@link EscalationDeniedError} — reviewer rejected the escalation
 * - {@link EscalationTimeoutError} — wait window elapsed without a decision
 * - {@link AtlaSentDeniedError} — hard deny (not hold/escalate); fail-closed
 * - {@link AtlaSentError} — transport / auth / server failure; fail-closed
 */
export async function protectOrEscalate(
  request: ProtectRequest,
  opts: ProtectOrEscalateOptions = {},
): Promise<ApprovalPermit> {
  try {
    const permit = await protect(request);
    return {
      ...permit,
      escalationId: "",
      resolvedBy: null,
      resolutionNote: null,
      resolvedAt: permit.timestamp,
      approvalBasis: "direct_policy",
    };
  } catch (err) {
    if (
      !(err instanceof AtlaSentDeniedError) ||
      (err.decision !== "hold" && err.decision !== "escalate")
    ) {
      throw err;
    }
  }

  // Create HITL escalation
  const proposedAction =
    opts.proposedAction ?? (request.context as Record<string, unknown> | undefined);
  const handle = await createEscalation({
    agent_id: opts.agentId ?? request.agent,
    escalation_reason:
      opts.escalationReason ??
      `Policy hold for "${request.action}" by "${request.agent}"`,
    ...(proposedAction !== undefined ? { proposed_action: proposedAction } : {}),
    ...(opts.riskScore !== undefined ? { risk_score: opts.riskScore } : {}),
    ...(opts.assignedToRole !== undefined ? { assigned_to_role: opts.assignedToRole } : {}),
    ...(opts.quorumRequired !== undefined ? { quorum_required: opts.quorumRequired } : {}),
    ...(opts.fallbackDecision !== undefined ? { fallback_decision: opts.fallbackDecision } : {}),
    ...(opts.timeoutAt !== undefined ? { timeout_at: opts.timeoutAt } : {}),
    ...(opts.metadata !== undefined ? { metadata: opts.metadata } : {}),
    ...(opts.apiKey !== undefined ? { apiKey: opts.apiKey } : {}),
    ...(opts.baseUrl !== undefined ? { baseUrl: opts.baseUrl } : {}),
  });

  opts.onEscalationCreated?.(handle);

  // Wait for human decision
  const outcome = await waitForEscalationApproval({
    escalationId: handle.escalationId,
    ...(opts.waitMs !== undefined ? { waitMs: opts.waitMs } : {}),
    ...(opts.pollIntervalMs !== undefined ? { pollIntervalMs: opts.pollIntervalMs } : {}),
    ...(opts.apiKey !== undefined ? { apiKey: opts.apiKey } : {}),
    ...(opts.baseUrl !== undefined ? { baseUrl: opts.baseUrl } : {}),
  });

  if (outcome.status === "rejected") throw new EscalationDeniedError(outcome);
  if (outcome.status === "timed_out") throw new EscalationTimeoutError(outcome);

  // Approved — return ApprovalPermit
  return {
    permitId: `escl_${handle.escalationId}`,
    permitHash: "",
    auditHash: outcome.escalation.id,
    reason: outcome.resolutionNote ?? "Approved by human reviewer",
    timestamp: outcome.resolvedAt ?? new Date().toISOString(),
    permitExpiresAt: null,
    escalationId: handle.escalationId,
    resolvedBy: outcome.resolvedBy,
    resolutionNote: outcome.resolutionNote,
    resolvedAt: outcome.resolvedAt ?? new Date().toISOString(),
    approvalBasis: "human_approval",
  };
}

// ── requestOverride ────────────────────────────────────────────────────────────

export interface RequestOverrideOptions {
  /** Human-readable justification. Required; max 2000 characters. */
  reason: string;
  /** The evaluation ID that was denied and should be overridden. */
  evaluationId: string;
  /** How long this override is valid, in seconds. Max 604800 (7 days). */
  ttlSeconds?: number;
  /** Arbitrary metadata to attach (e.g. liability attribution context). */
  metadata?: Record<string, unknown>;
  apiKey?: string;
  baseUrl?: string;
}

/**
 * Request a post-hoc override for a denied evaluation via POST /v1/overrides.
 *
 * The override starts in `pending` status and takes effect only after an
 * authorized actor approves it. Subsequent evaluations for the same action
 * will return `allow` while the override is `approved` and within its TTL.
 *
 * Attach `metadata.requested_by` for liability attribution.
 */
export async function requestOverride(
  opts: RequestOverrideOptions,
): Promise<OverrideV1> {
  const cfg = resolveConfig({
    ...(opts.apiKey !== undefined ? { apiKey: opts.apiKey } : {}),
    ...(opts.baseUrl !== undefined ? { baseUrl: opts.baseUrl } : {}),
  });

  const body: CreateOverrideRequest = {
    reason: opts.reason,
    evaluationId: opts.evaluationId,
    ...(opts.ttlSeconds !== undefined && { ttlSeconds: opts.ttlSeconds }),
    ...(opts.metadata !== undefined && { metadata: opts.metadata }),
  };

  return apiPost<OverrideV1>("/v1/overrides", body, cfg);
}
