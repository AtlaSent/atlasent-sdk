/**
 * AtlaSent HTTP client.
 *
 * Two public methods, both backed by native `fetch`:
 *   - {@link AtlaSentClient.evaluate}     → POST {baseUrl}/v1-evaluate
 *   - {@link AtlaSentClient.verifyPermit} → POST {baseUrl}/v1-verify-permit
 *
 * Fail-closed: a clean policy DENY is returned (not thrown), but
 * network, timeout, bad response, 4xx/5xx, and rate-limit conditions
 * all throw {@link AtlaSentError}.
 */

import { functionRegionHeaders } from "./functionRegion.js";
import type {
  AuditEventsPage,
  AuditEventsQuery,
  AuditExport,
} from "./audit.js";
import type { ReplayDecisionResponse } from "./replay.js";
import type {
  ReplayRequest,
  ReplayResponse,
  ReplayVarianceKind,
} from "./replay.js";
import {
  AtlaSentError,
  AtlaSentPermitMintFailedError,
  PERMIT_MINT_FAILURE_ERROR_CODES,
  StreamParseError,
  StreamTimeoutError,
  type AtlaSentErrorCode,
  type AtlaSentErrorInit,
} from "./errors.js";
import {
  TrustRootManager,
  getGlobalTrustRootManager,
  type TrustRootSnapshot,
} from "./trustRoot.js";
import { PRODUCTION_DEPLOY_ACTION } from "./types.js";
import type {
  ApiKeySelfResponse,
  AssertionSubmitInput,
  AssertionSubmitResult,
  AtlaSentClientOptions,
  ComplianceControlsResponse,
  ComplianceControlsQuery,
  ComplianceEvidencePackResponse,
  ComplianceEvidencePackQuery,
  Decision,
  AuditEventsResult,
  AuditExportRequest,
  AuditExportResult,
  ConstraintTrace,
  DecisionCanonical,
  DecisionStreamEvent,
  DeployGateEvidence,
  DeployGateRequest,
  DeployGateResponse,
  BatchEvalItem,
  BatchEvalResponse,
  EvaluateBatchResultItem,
  EvaluatePreflightResponse,
  SubscribeDecisionsOptions,
  EvaluateRequest,
  EvaluateResponse,
  GetPermitResponse,
  LicenseStatus,
  LicenseVerifyResult,
  ListPermitsRequest,
  ListPermitsResponse,
  PermitRecord,
  PermitValidResponse,
  RateLimitState,
  RevokePermitByIdInput,
  RevokePermitByIdResponse,
  RevokePermitRequest,
  RevokePermitResponse,
  StreamDecisionEvent,
  StreamEvent,
  StreamOptions,
  StreamProgressEvent,
  VerifyPermitByIdResponse,
  VerifyPermitRequest,
  VerifyPermitResponse,
} from "./types.js";
import {
  normalizeEvaluateRequest,
  resolveEvaluateIdentity,
  type LegacyEvaluateRequest,
  type V2EvaluateRequest,
} from "./compat.js";
import {
  computeBackoffMs,
  hasAttemptsLeft,
  isRetryable,
  mergePolicy,
  type RetryPolicy,
} from "./retry.js";
import type {
  GovernanceAgent,
  GovernanceAgentEvaluation,
  GovernanceAgentFinding,
  ListGovernanceAgentsResponse,
  ListGovernanceEvaluationsQuery,
  ListGovernanceEvaluationsResponse,
  ListGovernanceFindingsQuery,
  ListGovernanceFindingsResponse,
} from "./governanceAgents.js";
import type {
  HitlApprovalRecord,
  HitlApproveRequest,
  HitlChainHop,
  HitlCreateRequest,
  HitlEscalateRequest,
  HitlEscalation,
  HitlRejectRequest,
  ListHitlEscalationsRequest,
  ListHitlEscalationsResponse,
} from "./hitl.js";
import type {
  GovernanceGraphQueryType,
  GovernanceGraphQueryParams,
  GovernanceGraphQueryResponse,
  GovernanceGraphResultRow,
} from "./governanceGraph.js";
import type { IncidentTimelineResponse } from "./incidentReconstruction.js";
import type { ExplainAuthorityResult } from "./explainAuthority.js";
import type {
  ConnectorType,
  InstallConnectorInput,
  AuthenticateConnectorInput,
  UpsertEnforcementPolicyInput,
  ListConnectorsResponse,
  InstallConnectorResponse,
  AuthenticateConnectorResponse,
  SyncConnectorResponse,
  RevokeConnectorResponse,
  RotateCredentialsResponse,
  ListEnforcementPoliciesResponse,
  UpsertEnforcementPolicyResponse,
} from "./connectorManagement.js";
import type {
  ComputeOrgRiskOptions,
  ComputeOrgRiskResponse,
  GetLatestOrgRiskResponse,
  ListOrgRiskHistoryResponse,
} from "./orgRiskGraph.js";
import type {
  CrossOrgPermissionCheckRequest,
  CrossOrgPermissionCheckResult,
  CrossOrgPermissionCheckListParams,
} from "./crossOrgPermission.js";
import type {
  AnomalyResponseRule,
  AnomalyResponseEvent,
  CreateAnomalyResponseRuleRequest,
  TriggerAnomalyResponseRequest,
} from "./anomalyResponse.js";
import type {
  BudgetExceptionRequest,
  BudgetExceptionStatus,
  CreateBudgetExceptionRequest,
  ApproveBudgetExceptionRequest,
} from "./budgetExceptions.js";
import type {
  RegulatoryAuthorityLevel,
  RegulatoryEscalation,
  RegulatoryEscalationStatus,
  CreateRegulatoryEscalationRequest,
} from "./regulatoryEscalation.js";
import type {
  GovernanceSignalAction,
  RecordSignalActionRequest,
  RecordSignalOutcomeRequest,
  SignalActionSummary,
} from "./incentiveSignalFeedback.js";
import type {
  CrossOrgImpersonationGrant,
  CreateImpersonationGrantRequest,
  ImpersonationToken,
  ImpersonationValidationResult,
} from "./crossOrgImpersonation.js";
import {
  makeScimClient,
  type ScimSubClient,
} from "./scim.js";
import {
  makeEvidenceBundleClient,
  type EvidenceBundleSubClient,
} from "./evidence-bundle.js";
import {
  makeAuthClient,
  type AuthSubClient,
} from "./auth.js";
import {
  makeSsoClient,
  type SsoSubClient,
} from "./sso.js";
import {
  makeAccessGovernanceLogClient,
  type AccessGovernanceLogSubClient,
} from "./access-governance-log.js";
import {
  makeAuthorityIntelligenceClient,
  type AuthorityIntelligenceSubClient,
} from "./authorityIntelligence.js";
import {
  makeClinicalTrialsClient,
  type ClinicalTrialsSubClient,
} from "./clinical.js";
import {
  makeSmsOtpClient,
  type SmsOtpSubClient,
} from "./smsOtp.js";
import {
  makeUsageMeteringClient,
  type UsageMeteringSubClient,
} from "./usageMetering.js";
import type {
  CreateRbacRuleRequest,
  ListRbacRulesResponse,
  RbacRule,
} from "./rbacRules.js";
import type { GetApprovalSlaResponse } from "./approvalsSla.js";

const DEFAULT_BASE_URL = "https://api.atlasent.io";
const DEFAULT_TIMEOUT_MS = 10_000;
const SDK_VERSION = "2.18.0";

/**
 * Guard flag: emit the browser-environment warning at most once per
 * module-load lifetime. Prevents console spam when many client
 * instances are constructed in the same bundle.
 */
let warnedBrowser = false;
const V1_EVALUATE_BATCH_PATH = "/v1/evaluate/batch";
const V1_EVALUATE_BATCH_LEGACY_PATH = "/v1-evaluate-batch";
const V1_EVALUATE_STREAM_PATH = "/v1/evaluate/stream";
const V1_EVALUATE_STREAM_LEGACY_PATH = "/v1-evaluate-stream";

function _buildUserAgent(): string {
  const isNode =
    typeof process !== "undefined" &&
    typeof process?.versions?.node === "string";
  return isNode
    ? `@atlasent/sdk/${SDK_VERSION} node/${process.version}`
    : `@atlasent/sdk/${SDK_VERSION} browser`;
}

// Soft cap on top-level context properties. Mirrors the Python SDK
// (atlasent.models._CONTEXT_PROPERTIES_SOFT_CAP) and the OpenAPI
// `maxProperties: 64` declaration. The hosted API is the canonical
// enforcer; this helper warns the developer in dev rather than
// raising, so production traffic isn't broken on the day this ships.
const CONTEXT_PROPERTIES_SOFT_CAP = 64;

function _warnOversizeContext(
  context: Record<string, unknown> | undefined,
): void {
  if (context && Object.keys(context).length > CONTEXT_PROPERTIES_SOFT_CAP) {
    // eslint-disable-next-line no-console
    console.warn(
      `[atlasent] context has ${Object.keys(context).length} top-level keys ` +
        `(soft cap ${CONTEXT_PROPERTIES_SOFT_CAP}); the server may reject this. ` +
        "Pack richer payloads under a single top-level key.",
    );
  }
}

/**
 * Reject non-TLS base URLs unless the dev escape hatch is set.
 *
 * `ATLASENT_ALLOW_INSECURE_HTTP=1` (Node) or
 * `globalThis.ATLASENT_ALLOW_INSECURE_HTTP === "1"` (browser dev) permits
 * `http://` for local fixtures — production callers never set this.
 * Non-`http(s)` schemes (data:, file:, ...) are rejected unconditionally.
 *
 * Guards `process.env` access with an explicit `typeof` check so this
 * function is safe in browser and edge-runtime environments where
 * `process` is not defined as a global.
 */
function _enforceTls(baseUrl: string): string {
  const nodeEnvValue =
    typeof process !== "undefined" && process.env
      ? process.env.ATLASENT_ALLOW_INSECURE_HTTP
      : undefined;
  const allow =
    nodeEnvValue === "1" ||
    (globalThis as { ATLASENT_ALLOW_INSECURE_HTTP?: string })
      .ATLASENT_ALLOW_INSECURE_HTTP === "1";
  if (allow) return baseUrl;
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new AtlaSentError(`Invalid baseUrl: ${baseUrl}`, {
      code: "bad_request",
    });
  }
  if (parsed.protocol !== "https:") {
    throw new AtlaSentError(
      `AtlaSent baseUrl must use https:// (got ${parsed.protocol}). ` +
        `For local development, set ATLASENT_ALLOW_INSECURE_HTTP=1.`,
      { code: "bad_request" },
    );
  }
  return baseUrl;
}

// API-key prefix contract per atlasent-api/_shared/auth.ts:
//   "ask_live_<entropy>" — production
//   "ask_test_<entropy>" — non-production
// Validated client-side so a mis-pasted key (with whitespace, quotes,
// or a leftover wrapping char) trips loudly at construction rather
// than yielding a 401 mid-conversation.
const API_KEY_PATTERN = /^ask_(?:live|test)_[A-Za-z0-9_-]+$/;

function _validateApiKey(apiKey: string): string {
  if (typeof apiKey !== "string" || apiKey.length === 0) {
    throw new AtlaSentError("apiKey is required", { code: "invalid_api_key" });
  }
  if (!API_KEY_PATTERN.test(apiKey)) {
    const head = apiKey.slice(0, 8);
    throw new AtlaSentError(
      `AtlaSent apiKey does not match expected shape ` +
        `\`ask_(live|test)_<entropy>\` (got prefix=${JSON.stringify(head)}). ` +
        "Check for whitespace, quotes, or trailing characters.",
      { code: "invalid_api_key" },
    );
  }
  return apiKey;
}

/**
 * True when running in Node.js (or a Node-compatible server runtime that
 * exposes `process.versions.node`). False in browsers and browser-like
 * environments such as jsdom / Cloudflare Workers.
 */
const isNode =
  typeof process !== "undefined" && typeof process.versions?.node === "string";

/**
 * Node.js version string captured at module-load time so request code
 * never accesses `process` lazily — safe even if `process` is absent
 * (browsers) or replaced after load (bundlers, test environments).
 * `null` in every non-Node runtime.
 */
const NODE_VERSION: string | null = isNode ? process.version : null;

/**
 * Raw JSON shape received from `POST /v1-evaluate`.
 *
 * Canonical fields (per `atlasent-api/.../v1-evaluate/handler.ts`):
 *   decision: "allow" | "deny" | "hold" | "escalate"
 *   permit_token: string  (present iff decision === "allow")
 *   request_id: string
 *   expires_at?: string
 *   denial?: { reason, code }
 *
 * Legacy fields kept on the type so older atlasent-api deployments
 * (pre-handler.ts entry swap) still parse cleanly. The client below
 * checks canonical first and falls back to legacy.
 */
interface EvaluateWire {
  decision: "allow" | "deny" | "hold" | "escalate";
  permit_token?: string;
  request_id?: string;
  expires_at?: string;
  denial?: { reason?: string; code?: string };
  /**
   * Canonical top-level deny metadata emitted by handler.ts. The server
   * returns `deny_code` / `deny_reason` at the top level (NOT nested under
   * `denial`); the nested `denial` shape above is the contract/legacy form.
   * Read both so a deny is captured regardless of which shape the deployed
   * server emits.
   */
  deny_code?: string;
  deny_reason?: string;
  /**
   * Optional sub-object — present iff the request URL carried
   * `?include=constraint_trace`. Older atlasent-api deployments
   * omit this even when `include` was requested; the preflight
   * helper degrades to `null` in that case.
   */
  constraint_trace?: unknown;
  // Legacy passthrough.
  permitted?: boolean;
  decision_id?: string;
  reason?: string;
  audit_hash?: string;
  timestamp?: string;
  risk_envelope?: {
    weighted_score: number;
    engine_decision: string;
    envelope_decision: string;
    promoted: boolean;
    hard_blocks: string[];
    factors?: Array<{ factor: string; value: number; weight: number; reason: string }>;
  };
  // State-context response fields (control-plane v2+).
  risk_class?: string;
  authority_basis?: {
    kind: string;
    reference?: string;
    granted_by?: string;
    rationale?: string;
    expires_at?: string;
  };
  escalation_id?: string;
  /**
   * Two-stage authorization lifecycle (#1617): the human-approval
   * REQUIREMENT for this evaluation, distinct from its current
   * satisfaction state (`human_approval_status`).
   */
  human_approval_required?: boolean;
  /**
   * Two-stage authorization lifecycle (#1617): the human-approval
   * satisfaction state. Closed set:
   * `not_required | pending | satisfied | rejected | expired | revoked`.
   * Absent on responses from a runtime predating this field.
   */
  human_approval_status?: string;
}

interface EvaluateBatchWireItem {
  index: number;
  decision?: string;
  decision_id?: string;
  permit_token?: string | null;
  reason?: string | null;
  audit_entry_hash?: string;
  timestamp?: string;
  error?: string;
  message?: string;
  status?: number;
}

interface EvaluateBatchWire {
  batch_id: string;
  items: EvaluateBatchWireItem[];
  partial?: boolean;
  replayed?: boolean;
}

function deployGateEvidence(input: {
  permitId?: string;
  permitHash?: string;
  auditHash?: string;
  verifiedAt?: string;
}): DeployGateEvidence {
  const evidence: DeployGateEvidence = {};
  if (input.permitId) evidence.permitId = input.permitId;
  if (input.permitHash) evidence.permitHash = input.permitHash;
  if (input.auditHash) evidence.auditHash = input.auditHash;
  if (input.verifiedAt) evidence.verifiedAt = input.verifiedAt;
  return evidence;
}

/** Raw JSON shape received from `GET /v1-api-key-self`. */
interface ApiKeySelfWire {
  key_id: string;
  org_id: string;
  environment: string;
  scopes?: string[];
  allowed_cidrs?: string[] | null;
  rate_limit_per_minute: number;
  client_ip?: string | null;
  expires_at?: string | null;
}

/** Resolved evaluation window echoed back on compliance read endpoints. */
interface ComplianceWindowWire {
  from: string | null;
  to: string | null;
}

/** Status roll-up shared by both compliance read endpoints. */
interface ComplianceSummaryWire {
  enforced: number;
  partial: number;
  not_enforced: number;
  no_data: number;
  attested: number;
  total: number;
}

/** A single resolved control row from `GET /v1-compliance-controls`. */
interface ComplianceControlWire {
  clause_id: string;
  framework_code: string;
  section: string;
  title: string;
  requirement: string;
  atlasent_primitive: string;
  status_query: string;
  evidence_source: string;
  doc_ref: string | null;
  display_order: number;
  status: "enforced" | "partial" | "not_enforced" | "no_data" | "attested";
  metric: unknown;
}

/** Raw JSON shape received from `GET /v1-compliance-controls`. */
interface ComplianceControlsWire {
  framework: string | null;
  window: ComplianceWindowWire;
  generated_at: string;
  summary: ComplianceSummaryWire;
  controls: ComplianceControlWire[];
  truncated: boolean;
}

/** A single control row inside an evidence-pack `bundle`. */
interface ComplianceEvidenceControlWire {
  clause_id: string;
  framework_code: string;
  section: string;
  title: string;
  requirement: string;
  atlasent_primitive: string;
  status_query: string;
  evidence_source: string;
  status: "enforced" | "partial" | "not_enforced" | "no_data" | "attested";
  metric: unknown;
}

/** The self-contained, hashable evidence payload. */
interface ComplianceEvidenceBundleWire {
  schema: string;
  framework: string;
  window: ComplianceWindowWire;
  org_id: string;
  summary: ComplianceSummaryWire;
  controls: ComplianceEvidenceControlWire[];
}

/** Raw JSON shape received from `GET /v1-compliance-evidence-pack`. */
interface ComplianceEvidencePackWire {
  framework: string;
  window: ComplianceWindowWire;
  generated_at: string;
  summary: ComplianceSummaryWire;
  sha256: string;
  signature: string;
  signing_status: string;
  key_id: string | null;
  bundle: ComplianceEvidenceBundleWire;
}

/**
 * Raw JSON shape received from `POST /v1-verify-permit`.
 *
 * Canonical fields:
 *   valid: boolean
 *   outcome: "allow" | "deny"
 *   verify_error_code?: string  (populated on outcome === "deny")
 *   reason?: string
 *
 * Legacy `verified` kept for backward-compat with older deployments.
 */
interface VerifyPermitWire {
  valid: boolean;
  outcome: "allow" | "deny";
  verify_error_code?: string;
  reason?: string;
  expires_at?: string | null;
  // Legacy passthrough.
  verified?: boolean;
  permit_hash?: string;
  timestamp?: string;
}

/**
 * Build the `/v1-evaluate` request body from either accepted input shape.
 *
 * Exported and used as the SINGLE construction site on purpose. `protect()`
 * has to hash the body it actually posts, because the runtime binds the permit
 * to its own hash of that body and `/v1-verify-permit` compares the presented
 * digest against it verbatim. A second, hand-written "mirror" of this
 * construction is exactly the shape that fails: the Python SDK's mirror
 * omitted `state_snapshot`, so every `protect(state_snapshot=...)` call was a
 * guaranteed `PAYLOAD_MISMATCH`. With one function there is nothing to drift.
 *
 * The server strips `traceparent` / `shadow` / `explain` before hashing, so a
 * caller that hashes this output must strip the same three.
 */
export function buildEvaluateBody(
  input: EvaluateRequest | LegacyEvaluateRequest,
): Record<string, unknown> {
  // Run the dual-shape bridge: legacy {action, agent} → {action_type, actor_id}.
  // For callers already on the current EvaluateRequest shape the bridge is a
  // transparent pass-through (no warn, no allocation).
  const normalized = normalizeEvaluateRequest(
    input as LegacyEvaluateRequest | V2EvaluateRequest,
  );

  const body: Record<string, unknown> = {
    action_type: normalized.action_type,
    actor_id: normalized.actor_id,
    context: normalized.context ?? {},
  };
  if (normalized.explain !== undefined) body.explain = normalized.explain;
  if (normalized.environment !== undefined) body.environment = normalized.environment;
  if (normalized.resource !== undefined) body.resource = normalized.resource;
  if (normalized.current_state !== undefined) body.current_state = normalized.current_state;
  if (normalized.proposed_state !== undefined) body.proposed_state = normalized.proposed_state;
  if (normalized.execution_binding !== undefined) body.execution_binding = normalized.execution_binding;
  // TOP-LEVEL, never inside `context` — the handler destructures it from the
  // body alongside `context`, so a copy placed within `context` is not a
  // binding and is dropped without an error. Forwarded verbatim: the
  // runtime's bare-hex gate is the authority on the accepted form, and
  // `ProtectRequest.executionPayloadHash` normalizes before it reaches here.
  if (normalized.execution_payload_hash !== undefined) body.execution_payload_hash = normalized.execution_payload_hash;
  if (normalized.state_snapshot !== undefined) body.state_snapshot = normalized.state_snapshot;
  // These three are genuinely read server-side (resolveProfile(),
  // the emergency-override gate, and the quorum check respectively) —
  // silently dropping them here would mean a caller's evaluation_profile
  // selection, emergency override, or completion_proofs never actually
  // reach the runtime despite the public EvaluateRequest type declaring
  // them as accepted fields.
  if (normalized.evaluation_profile !== undefined) body.evaluation_profile = normalized.evaluation_profile;
  if (normalized.override !== undefined) body.override = normalized.override;
  if (normalized.completion_proofs !== undefined) body.completion_proofs = normalized.completion_proofs;
  return body;
}

export class AtlaSentClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly userAgent: string;
  /** Edge-function region headers, resolved once from baseUrl (see ./functionRegion). */
  private readonly regionHeaders: Record<string, string>;
  private readonly retryPolicy: Required<RetryPolicy>;

  /** SCIM 2.0 provisioning sub-client. Access as `client.scim`. */
  readonly scim: ScimSubClient;
  /** Evidence bundle sub-client. Access as `client.evidenceBundles`. */
  readonly evidenceBundles: EvidenceBundleSubClient;
  /** Auth / token management sub-client. Access as `client.auth`. */
  readonly auth: AuthSubClient;
  /** SSO administration sub-client. Access as `client.sso`. */
  readonly sso: SsoSubClient;
  /** Access governance log sub-client. Access as `client.accessGovernanceLog`. */
  readonly accessGovernanceLog: AccessGovernanceLogSubClient;
  /** Authority intelligence sub-client. Access as `client.authorityIntelligence`. */
  readonly authorityIntelligence: AuthorityIntelligenceSubClient;
  /** Clinical trial unblinding gate sub-client. Access as `client.clinicalTrials`. */
  readonly clinicalTrials: ClinicalTrialsSubClient;
  /** SMS OTP step-up authentication sub-client. Access as `client.smsOtp`. */
  readonly smsOtp: SmsOtpSubClient;
  /** Usage metering sub-client. Access as `client.usageMetering`. */
  readonly usageMetering: UsageMeteringSubClient;
  /** Trust-root snapshot manager for this client instance. */
  readonly trustRoot: TrustRootManager;

  constructor(options: AtlaSentClientOptions) {
    if (!options.apiKey || typeof options.apiKey !== "string") {
      throw new AtlaSentError("apiKey is required", {
        code: "invalid_api_key",
      });
    }
    if (typeof AbortSignal.timeout !== "function") {
      throw new AtlaSentError(
        "@atlasent/sdk requires AbortSignal.timeout, which is not available in this runtime. " +
          "Minimum supported browsers: Chrome 103+, Firefox 100+, Safari 16+. " +
          "Upgrade your browser or add an AbortSignal.timeout polyfill.",
        { code: "network" },
      );
    }
    if (
      !warnedBrowser &&
      typeof (globalThis as Record<string, unknown>)["window"] !== "undefined" &&
      typeof process === "undefined"
    ) {
      warnedBrowser = true;
      // eslint-disable-next-line no-console
      console.warn(
        "[@atlasent/sdk] Running in a browser environment. " +
          "API keys should not be exposed in client-side bundles. " +
          "Use a server-side proxy instead.",
      );
    }
    this.apiKey = _validateApiKey(options.apiKey);
    this.baseUrl = _enforceTls(options.baseUrl ?? DEFAULT_BASE_URL).replace(
      /\/+$/,
      "",
    );
    this.regionHeaders = functionRegionHeaders(this.baseUrl, options.functionRegion);
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.userAgent = _buildUserAgent();
    this.retryPolicy = mergePolicy(options.retryPolicy ?? {});
    this.scim = makeScimClient(
      (path, body, query) => this._post(path, body, query),
      (path, query) => this._get(path, query),
      (path, body) => this._put(path, body),
      (path) => this._delete(path),
    );
    this.evidenceBundles = makeEvidenceBundleClient(
      (path, body) => this._post(path, body),
      (path, query) => this._get(path, query),
      (path) => this._getRaw(path),
    );
    this.auth = makeAuthClient(
      (path, body) => this._post(path, body),
      (path) => this._get(path),
    );
    this.sso = makeSsoClient(
      (path, query) => this._get(path, query),
      (path, body) => this._post(path, body),
      (path, body) => this._patch(path, body),
      (path) => this._delete(path),
    );
    this.accessGovernanceLog = makeAccessGovernanceLogClient(
      (path, query) => this._get(path, query),
    );
    this.authorityIntelligence = makeAuthorityIntelligenceClient(
      (path, query) => this._get(path, query),
    );
    this.clinicalTrials = makeClinicalTrialsClient(
      (path, query) => this._get(path, query),
      (path, body) => this._post(path, body),
    );
    this.smsOtp = makeSmsOtpClient(
      this.baseUrl,
      this.fetchImpl,
    );
    this.usageMetering = makeUsageMeteringClient(
      (path, query) => this._get(path, query),
    );
    // Wire trust-root manager. Prefer custom options over the global manager
    // so clients with custom trustRootUrl or trustSnapshotRefreshMs get their
    // own manager; otherwise share the process-global singleton.
    if (options.trustRootUrl !== undefined || options.trustSnapshotRefreshMs !== undefined) {
      const globalSnap = getGlobalTrustRootManager({ disableRefresh: true }).getSnapshot();
      this.trustRoot = new TrustRootManager(globalSnap, {
        ...(options.trustRootUrl !== undefined && { refreshBaseUrl: options.trustRootUrl }),
        ...(options.trustSnapshotRefreshMs !== undefined && { refreshIntervalMs: options.trustSnapshotRefreshMs }),
      });
    } else {
      this.trustRoot = getGlobalTrustRootManager();
    }
    // Emit expiry warning once at construction time.
    this.trustRoot.checkExpiry();
  }

  /** Return the current trust-root snapshot (pinned or last successful refresh). */
  getTrustSnapshot(): TrustRootSnapshot {
    return this.trustRoot.getSnapshot();
  }

  /**
   * Ask the policy engine whether an agent action is permitted.
   *
   * Accepts either the current v2.0 shape (`action_type` / `actor_id`)
   * or the legacy v1.x shape (`action` / `agent`). Legacy callers
   * receive a deprecation warning via `console.warn`; the shim is
   * handled by {@link normalizeEvaluateRequest} and will be removed
   * in v3.0.0.
   *
   * A "deny" is **not** thrown — it is returned in
   * `response.decision`. Network errors, invalid API key, rate
   * limits, timeouts, and malformed responses throw
   * {@link AtlaSentError}.
   */
  async evaluate(
    input: EvaluateRequest | LegacyEvaluateRequest,
  ): Promise<EvaluateResponse> {
    _warnOversizeContext(input.context);

    const body = buildEvaluateBody(input);
    const { body: wire, rateLimit } = await this.post<EvaluateWire>(
      "/v1-evaluate",
      body,
    );

    // Normalise decision to lowercase canonical form. API responses may
    // arrive as uppercase (legacy deployments) or lowercase (canonical);
    // we always emit lowercase so callers can rely on a stable vocabulary.
    let decision = (
      typeof wire.decision === "string"
        ? wire.decision.toLowerCase()
        : wire.decision
    ) as EvaluateWire["decision"] | undefined;

    // Tolerate both canonical {decision, permit_token} and legacy
    // {permitted, decision_id} server responses.
    if (decision === undefined && typeof wire.permitted === "boolean") {
      decision = wire.permitted ? "allow" : "deny";
    }
    const permitToken = wire.permit_token ?? wire.decision_id;

    if (
      decision !== "allow" &&
      decision !== "deny" &&
      decision !== "hold" &&
      decision !== "escalate"
    ) {
      throw new AtlaSentError(
        "Malformed response from /v1-evaluate: missing `decision` (or legacy `permitted`)",
        { code: "bad_response" },
      );
    }
    if (
      decision === "allow" &&
      (typeof permitToken !== "string" || permitToken.length === 0)
    ) {
      // #1634: a 2xx allow response missing permit_token is the same
      // "allow, but no executable authority" outcome as the documented
      // non-2xx permit_signing_unavailable envelope the request() layer
      // already handles below — defensive fallback in case a future
      // response shape ever resolves this way over a 2xx status. Same
      // distinct error class either way.
      throw new AtlaSentPermitMintFailedError(
        "Malformed response from /v1-evaluate: decision='allow' but no `permit_token` (or legacy `decision_id`)",
      );
    }

    const reason = wire.deny_reason ?? wire.denial?.reason ?? wire.reason ?? "";
    const denyCode = wire.deny_code ?? wire.denial?.code ?? null;
    const permitId = permitToken ?? "";
    return {
      decision,
      decision_canonical: decision,
      evaluationId: permitId,
      permitId,
      // /v1-evaluate does not return a control-plane-shaped Permit body;
      // callers needing the full record fetch GET /v1/permits/:id.
      permit: null,
      permitToken: decision === "allow" ? (permitToken ?? null) : null,
      reasons: reason ? [reason] : [],
      reason,
      deny_code: decision === "allow" ? null : denyCode,
      auditHash: wire.audit_hash ?? "",
      timestamp: wire.timestamp ?? "",
      rateLimit,
      ...(wire.risk_envelope && {
        riskEnvelope: {
          weightedScore: wire.risk_envelope.weighted_score,
          engineDecision: wire.risk_envelope.engine_decision as Decision,
          envelopeDecision: wire.risk_envelope.envelope_decision as Decision,
          promoted: wire.risk_envelope.promoted,
          hardBlocks: wire.risk_envelope.hard_blocks ?? [],
          ...(wire.risk_envelope.factors && { factors: wire.risk_envelope.factors }),
        },
      }),
      ...(wire.risk_class !== undefined && { riskClass: wire.risk_class }),
      ...(wire.authority_basis && {
        authorityBasis: {
          kind: wire.authority_basis.kind as NonNullable<EvaluateResponse["authorityBasis"]>["kind"],
          ...(wire.authority_basis.reference !== undefined && { reference: wire.authority_basis.reference }),
          ...(wire.authority_basis.granted_by !== undefined && { grantedBy: wire.authority_basis.granted_by }),
          ...(wire.authority_basis.rationale !== undefined && { rationale: wire.authority_basis.rationale }),
          ...(wire.authority_basis.expires_at !== undefined && { expiresAt: wire.authority_basis.expires_at }),
        },
      }),
      ...(wire.escalation_id !== undefined && { escalationId: wire.escalation_id }),
      ...(wire.human_approval_required !== undefined && {
        humanApprovalRequired: wire.human_approval_required,
      }),
      ...(wire.human_approval_status !== undefined && {
        humanApprovalStatus: wire.human_approval_status as NonNullable<
          EvaluateResponse["humanApprovalStatus"]
        >,
      }),
    };
  }

  /**
   * Batch evaluate — send up to 100 decisions in a single round-trip.
   *
  * Wraps `POST /v1/evaluate/batch` (with fallback to
  * `POST /v1-evaluate-batch` on older runtimes). The server evaluates each item
   * against the active policy bundle and returns results in the same
   * order as the input. One rate-limit token is consumed for the
   * whole batch, and one audit-chain entry lists every included
   * decision id.
   *
   * A per-item policy `deny` is **not** thrown — it appears as
   * `item.decision === "deny"` in the returned items. A whole-batch
   * network error, 4xx, or 5xx throws {@link AtlaSentError}.
   *
   * Requires the `v2_batch` tenant feature flag to be enabled on the
   * org (returns 404 when off). Requires scope `evaluate:write`.
   *
   * @param requests - 1–100 evaluate items.
   * @param batchId  - Optional caller-supplied UUID for idempotency.
   *   A retried call with the same `batchId` and identical items
   *   returns the cached response within 24 h (`replayed: true`).
   */
  async evaluateBatch(
    requests: BatchEvalItem[],
    batchId?: string,
  ): Promise<BatchEvalResponse> {
    if (!Array.isArray(requests) || requests.length === 0) {
      throw new AtlaSentError(
        "evaluateBatch: requests must be a non-empty array",
        { code: "bad_request" },
      );
    }
    if (requests.length > 100) {
      throw new AtlaSentError(
        `evaluateBatch: requests.length ${requests.length} exceeds the 100-item cap`,
        { code: "bad_request" },
      );
    }

    const wireItems = requests.map((r) => ({
      action_type: r.action,
      actor_id: r.agent,
      context: r.context ?? {},
    }));

    const wireBody: Record<string, unknown> = { items: wireItems };
    if (batchId) wireBody.batch_id = batchId;

    const { body: wire, rateLimit } = await this.postWithPathFallback<EvaluateBatchWire>(
      V1_EVALUATE_BATCH_PATH,
      V1_EVALUATE_BATCH_LEGACY_PATH,
      wireBody,
    );

    const items: EvaluateBatchResultItem[] = (wire.items ?? []).map(
      (item: EvaluateBatchWireItem) => {
        const rawDecision = typeof item.decision === "string"
          ? item.decision.toLowerCase()
          : undefined;
        const decision = (
          rawDecision === "allow" ||
          rawDecision === "deny" ||
          rawDecision === "hold" ||
          rawDecision === "escalate"
            ? rawDecision
            : undefined
        ) as DecisionCanonical | undefined;

        return {
          index: item.index,
          ...(decision !== undefined ? { decision } : {}),
          ...(item.decision_id ? { decisionId: item.decision_id } : {}),
          ...(item.permit_token != null ? { permitToken: item.permit_token } : {}),
          ...(item.reason != null ? { reason: item.reason } : {}),
          ...(item.audit_entry_hash ? { auditHash: item.audit_entry_hash } : {}),
          ...(item.timestamp ? { timestamp: item.timestamp } : {}),
          ...(item.error ? { error: item.error } : {}),
          ...(item.message ? { message: item.message } : {}),
        } satisfies EvaluateBatchResultItem;
      },
    );

    return {
      batchId: wire.batch_id,
      items,
      partial: wire.partial ?? false,
      ...(wire.replayed ? { replayed: wire.replayed } : {}),
      rateLimit,
    };
  }

  /**
   * Subscribe to a live stream of decisions for this org.
   *
   * `v1-decisions-stream` is deployed in production (re-enabled
   * 2026-06-01; present in `runtime-functions.json`) — it is not one
   * of the endpoints in `runtime-functions-disabled.json`. It remains
   * gated per-tenant behind the `v2_decisions_stream` feature flag
   * (404 when off for a given org), which is a normal rollout gate,
   * not a "not deployed" marker.
   *
   * Wraps `GET /v1-decisions-stream`. The server emits one SSE frame
   * per audit event and sends a heartbeat every 15 s. The session
   * auto-closes after `maxSeconds` (default 30 min); reconnect with
   * the last received `event.id` to resume without replaying history.
   *
   * ```ts
   * const controller = new AbortController();
   * for await (const event of client.subscribeDecisions({ signal: controller.signal })) {
   *   if (event.type === "heartbeat") continue;
   *   console.log(event.type, event.decision, event.actorId);
   *   if (event.type === "session_end") break; // reconnect
   * }
   * ```
   *
   * Requires scope `audit:read`. Requires the `v2_decisions_stream`
   * tenant feature flag (returns 404 when off).
   */
  async *subscribeDecisions(
    opts: SubscribeDecisionsOptions = {},
  ): AsyncGenerator<DecisionStreamEvent> {
    const url = new URL(`${this.baseUrl}/v1-decisions-stream`);
    if (opts.types?.length) url.searchParams.set("types", opts.types.join(","));
    if (opts.actorId) url.searchParams.set("actor_id", opts.actorId);
    if (opts.maxSeconds !== undefined) url.searchParams.set("max_seconds", String(opts.maxSeconds));

    const headers: Record<string, string> = {
      Accept: "text/event-stream",
      Authorization: `Bearer ${this.apiKey}`,
      "User-Agent": this.userAgent,
      ...this.regionHeaders,
      // ADR-025: declare the wire-protocol version we were built
      // against. Runtime serves this version's response shape; older
      // versions outside the compatibility window get 426.
      "X-AtlaSent-Protocol-Version": "1",
    };
    if (opts.lastEventId) headers["Last-Event-ID"] = opts.lastEventId;

    let response: Response;
    try {
      response = await this.fetchImpl(url.toString(), {
        method: "GET",
        headers,
        ...(opts.signal ? { signal: opts.signal } : {}),
      });
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") return;
      throw new AtlaSentError(
        `Failed to connect to decisions stream: ${err instanceof Error ? err.message : String(err)}`,
        { code: "network" },
      );
    }

    if (!response.ok) {
      const code = response.status === 401 ? "invalid_api_key" : "server_error";
      throw new AtlaSentError(
        `Decisions stream returned ${response.status}`,
        { code, status: response.status },
      );
    }

    if (!response.body) {
      throw new AtlaSentError("Decisions stream response has no body", { code: "bad_response" });
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buf = "";

    try {
      while (true) {
        let chunk: Awaited<ReturnType<typeof reader.read>>;
        try {
          chunk = await reader.read();
        } catch (err) {
          if (err instanceof Error && err.name === "AbortError") return;
          throw new AtlaSentError(
            `Decisions stream read error: ${err instanceof Error ? err.message : String(err)}`,
            { code: "network" },
          );
        }
        if (chunk.done) break;

        buf += decoder.decode(chunk.value, { stream: true });
        const rawBlocks = buf.split("\n\n");
        buf = rawBlocks.pop() ?? "";

        for (const block of rawBlocks) {
          if (!block.trim()) continue;

          // SSE comment / heartbeat line (": …")
          if (block.trimStart().startsWith(":")) {
            yield { type: "heartbeat" };
            continue;
          }

          let id: string | undefined;
          let eventType = "audit_event";
          let dataLine = "";

          for (const line of block.split("\n")) {
            if (line.startsWith("id:")) id = line.slice(3).trim();
            else if (line.startsWith("event:")) eventType = line.slice(6).trim();
            else if (line.startsWith("data:")) dataLine = line.slice(5).trim();
          }

          if (!dataLine) continue;

          let parsed: Record<string, unknown>;
          try {
            parsed = JSON.parse(dataLine) as Record<string, unknown>;
          } catch {
            continue;
          }

          if (eventType === "session_end") {
            yield { ...(id !== undefined ? { id } : {}), type: "session_end", payload: parsed };
            return;
          }

          const decision = typeof parsed.decision === "string"
            ? parsed.decision.toLowerCase() as DecisionCanonical
            : undefined;

          yield {
            ...(id !== undefined ? { id } : {}),
            type: eventType,
            ...(decision ? { decision } : {}),
            ...(typeof parsed.actor_id === "string" ? { actorId: parsed.actor_id } : {}),
            ...(typeof parsed.resource_type === "string" ? { resourceType: parsed.resource_type } : {}),
            ...(typeof parsed.resource_id === "string" ? { resourceId: parsed.resource_id } : {}),
            ...(parsed.payload && typeof parsed.payload === "object" ? { payload: parsed.payload as Record<string, unknown> } : {}),
            ...(typeof parsed.hash === "string" ? { hash: parsed.hash } : {}),
            ...(typeof parsed.previous_hash === "string" ? { previousHash: parsed.previous_hash } : {}),
            ...(typeof parsed.occurred_at === "string" ? { occurredAt: parsed.occurred_at } : {}),
          } satisfies DecisionStreamEvent;
        }
      }
    } finally {
      reader.releaseLock();
    }
  }

  /**
   * Pre-flight evaluation that always returns the constraint trace.
   *
   * Wraps `POST /v1-evaluate?include=constraint_trace`. Use this from
   * a workflow's submission step to surface trivial defects (missing
   * fields, wrong roles, mis-set context) BEFORE pushing the request
   * onto an approval queue — only requests that would actually pass
   * make it through to a human reviewer.
   *
   * Returns an {@link EvaluatePreflightResponse} carrying the regular
   * {@link EvaluateResponse} plus the {@link ConstraintTrace}. Unlike
   * {@link evaluate}, this method does NOT mark a non-allow as a
   * thrown condition — the whole point is to inspect both the outcome
   * AND the per-policy trace, so the caller branches on
   * `result.evaluation.decision` and reads `result.constraintTrace`
   * to render the failing stages.
   *
   * The constraint-trace shape mirrors `ConstraintTraceResponse` in
   * atlasent-api (`packages/types/src/index.ts`). On older
   * atlasent-api deployments that omit the trace, `constraintTrace`
   * is `null` rather than throwing — forward-compatible degradation.
   *
   * Performance: one extra round-trip on submission. Latency is
   * comparable to {@link evaluate}; the response body is fuller
   * (includes the per-stage trace) so the wire payload is larger.
   * If the caller does not need the trace, prefer {@link evaluate}.
   */
  async evaluatePreflight(
    input: EvaluateRequest,
  ): Promise<EvaluatePreflightResponse> {
    _warnOversizeContext(input.context);
    // Accept both the canonical {action_type, actor_id} and the legacy
    // {action, agent} shape; always serialize the canonical wire.
    const normalized = normalizeEvaluateRequest(
      input as LegacyEvaluateRequest | V2EvaluateRequest,
    );
    const body = {
      action_type: normalized.action_type,
      actor_id: normalized.actor_id,
      context: normalized.context ?? {},
    };
    const query = new URLSearchParams({ include: "constraint_trace" });
    const { body: wire, rateLimit } = await this.post<EvaluateWire>(
      "/v1-evaluate",
      body,
      query,
    );

    // Normalise decision to lowercase canonical form.
    let decision = (
      typeof wire.decision === "string"
        ? wire.decision.toLowerCase()
        : wire.decision
    ) as EvaluateWire["decision"] | undefined;

    if (decision === undefined && typeof wire.permitted === "boolean") {
      decision = wire.permitted ? "allow" : "deny";
    }
    if (
      decision !== "allow" &&
      decision !== "deny" &&
      decision !== "hold" &&
      decision !== "escalate"
    ) {
      throw new AtlaSentError(
        "Malformed response from /v1-evaluate: missing `decision` (or legacy `permitted`)",
        { code: "bad_response" },
      );
    }
    const permitToken = wire.permit_token ?? wire.decision_id;

    const reason = wire.deny_reason ?? wire.denial?.reason ?? wire.reason ?? "";
    const denyCode = wire.deny_code ?? wire.denial?.code ?? null;
    const permitId = permitToken ?? "";
    const evaluation: EvaluateResponse = {
      decision,
      decision_canonical: decision,
      evaluationId: permitId,
      permitId,
      // /v1-evaluate does not return a control-plane-shaped Permit body;
      // callers needing the full record fetch GET /v1/permits/:id.
      permit: null,
      permitToken: decision === "allow" ? (permitToken ?? null) : null,
      reasons: reason ? [reason] : [],
      reason,
      deny_code: decision === "allow" ? null : denyCode,
      auditHash: wire.audit_hash ?? "",
      timestamp: wire.timestamp ?? "",
      rateLimit,
      ...(wire.risk_envelope && {
        riskEnvelope: {
          weightedScore: wire.risk_envelope.weighted_score,
          engineDecision: wire.risk_envelope.engine_decision as Decision,
          envelopeDecision: wire.risk_envelope.envelope_decision as Decision,
          promoted: wire.risk_envelope.promoted,
          hardBlocks: wire.risk_envelope.hard_blocks ?? [],
          ...(wire.risk_envelope.factors && { factors: wire.risk_envelope.factors }),
        },
      }),
      ...(wire.human_approval_required !== undefined && {
        humanApprovalRequired: wire.human_approval_required,
      }),
      ...(wire.human_approval_status !== undefined && {
        humanApprovalStatus: wire.human_approval_status as NonNullable<
          EvaluateResponse["humanApprovalStatus"]
        >,
      }),
    };

    // Forward-compat: if the server omits `constraint_trace` (older
    // atlasent-api version), surface trace=null rather than throwing.
    // Unknown engine-side keys inside the trace are tolerated by the
    // ConstraintTrace interface's index signature.
    let constraintTrace: ConstraintTrace | null = null;
    if (
      wire.constraint_trace !== undefined &&
      wire.constraint_trace !== null &&
      typeof wire.constraint_trace === "object"
    ) {
      constraintTrace = wire.constraint_trace as ConstraintTrace;
    }

    return { evaluation, constraintTrace };
  }

  /**
   * Verify that a previously issued permit is still valid.
   *
   * @deprecated Use {@link verifyPermitById} — the canonical REST
   * surface (`POST /v1/permits/{id}/verify`) returns the unified
   * verification envelope plus the full {@link PermitRecord}, instead
   * of the legacy `{verified, outcome, permitHash}` shape this method
   * emits. Will be removed in `@atlasent/sdk@3`.
   *
   * A `verified: false` response is **not** thrown — inspect the
   * returned object. Only transport / server errors throw.
   */
  async verifyPermit(
    input: VerifyPermitRequest,
  ): Promise<VerifyPermitResponse> {
    _warnOversizeContext(input.context);
    // Canonical wire shape per handler.ts: only permit_token is required.
    // action_type / actor_id are optional cross-checks; context / api_key
    // are NOT consulted by the verify handler.
    const body: Record<string, unknown> = {
      permit_token: input.permitId,
      action_type: input.action ?? "",
      actor_id: input.agent ?? "",
    };
    if (input.environment !== undefined) {
      body.environment = input.environment;
    }
    if (input.execution_hash !== undefined) {
      body.execution_hash = input.execution_hash;
    }
    const { body: wire, rateLimit } = await this.post<VerifyPermitWire>(
      "/v1-verify-permit",
      body,
    );

    // Tolerate both canonical {valid, outcome} and legacy {verified} server
    // responses.
    const valid = typeof wire.valid === "boolean" ? wire.valid : wire.verified;
    if (typeof valid !== "boolean") {
      throw new AtlaSentError(
        "Malformed response from /v1-verify-permit: missing `valid` (or legacy `verified`)",
        { code: "bad_response" },
      );
    }

    return {
      verified: valid,
      outcome: wire.outcome ?? "",
      permitHash: wire.permit_hash ?? "",
      timestamp: wire.timestamp ?? "",
      expiresAt: wire.expires_at ?? null,
      rateLimit,
    };
  }

  /**
   * Run the canonical Deploy Gate V1 flow:
   * evaluate `production.deploy`, verify the issued permit server-side,
   * and return allow/block plus audit/evidence metadata.
   *
   * This helper never treats a signed/offline permit artifact as sufficient
   * authorization. Execution is allowed only when `POST /v1-evaluate` returns
   * `decision: "allow"` with a permit AND `POST /v1-verify-permit` returns
   * `verified: true` / `valid: true`.
   */
  async deployGate(input: DeployGateRequest = {}): Promise<DeployGateResponse> {
    const agent = input.agent ?? "ci-deploy-bot";
    const action = input.action ?? PRODUCTION_DEPLOY_ACTION;
    const context = input.context ?? {};
    const environment =
      typeof (context as Record<string, unknown>).environment === "string"
        ? ((context as Record<string, unknown>).environment as string)
        : typeof (context as Record<string, unknown>).environment_name === "string"
          ? ((context as Record<string, unknown>).environment_name as string)
          : undefined;

    const evaluation = await this.evaluate({
      agent,
      action,
      context,
      ...(input.stateSnapshot !== undefined
        ? { state_snapshot: input.stateSnapshot }
        : {}),
    } as Parameters<typeof this.evaluate>[0]);
    if (evaluation.decision !== "allow") {
      return {
        allowed: false,
        evaluation,
        reason:
          evaluation.reason ||
          `Deploy Gate blocked by decision=${evaluation.decision}`,
        evidence: deployGateEvidence({
          permitId: evaluation.permitId,
          auditHash: evaluation.auditHash,
        }),
      };
    }

    const verification = await this.verifyPermit({
      permitId: evaluation.permitId,
      agent,
      action,
      context,
      ...(environment !== undefined ? { environment } : {}),
    });

    if (!verification.verified) {
      return {
        allowed: false,
        evaluation,
        verification,
        reason: verification.outcome
          ? `Deploy Gate blocked by permit verification outcome=${verification.outcome}`
          : "Deploy Gate blocked because permit verification failed",
        evidence: deployGateEvidence({
          permitId: evaluation.permitId,
          permitHash: verification.permitHash,
          auditHash: evaluation.auditHash,
          verifiedAt: verification.timestamp,
        }),
      };
    }

    return {
      allowed: true,
      evaluation,
      verification,
      reason: evaluation.reason || "Deploy Gate permit verified",
      evidence: deployGateEvidence({
        permitId: evaluation.permitId,
        permitHash: verification.permitHash,
        auditHash: evaluation.auditHash,
        verifiedAt: verification.timestamp,
      }),
    };
  }

  /**
   * Revoke a previously-issued permit so it can no longer pass
   * {@link verifyPermit}.
   *
   * @deprecated Use {@link revokePermitById} — the canonical REST
   * surface (`POST /v1/permits/{id}/revoke`) returns the full updated
   * {@link PermitRecord} with `revoked_at`/`revoked_by`/`revoke_reason`
   * populated, instead of the legacy `{revoked, permitId}` envelope
   * this method emits. Will be removed in `@atlasent/sdk@3`.
   *
   * Use this when an agent's action is cancelled, superseded, or
   * determined to be unauthorized after the fact. The revocation is
   * recorded in the audit log with the optional `reason`.
   *
   * Throws {@link AtlaSentError} on transport / auth failures.
   */
  async revokePermit(
    input: RevokePermitRequest,
  ): Promise<RevokePermitResponse> {
    const body = {
      decision_id: input.permitId,
      reason: input.reason ?? "",
      api_key: this.apiKey,
    };
    const { body: wire, rateLimit } = await this.post<{
      revoked: boolean;
      decision_id: string;
      revoked_at?: string;
      audit_hash?: string;
    }>("/v1-revoke-permit", body);

    if (
      typeof wire.revoked !== "boolean" ||
      typeof wire.decision_id !== "string"
    ) {
      throw new AtlaSentError(
        "Malformed response from /v1-revoke-permit: missing `revoked` or `decision_id`",
        { code: "bad_response" },
      );
    }

    return {
      revoked: wire.revoked,
      permitId: wire.decision_id,
      revokedAt: wire.revoked_at,
      auditHash: wire.audit_hash,
      rateLimit,
    };
  }

  /**
   * Revoke a permit through the canonical REST surface
   * (`POST /v1/permits/{permitId}/revoke`).
   *
   * Returns the full updated {@link PermitRecord} with `status === 'revoked'`
   * and `revoked_at` / `revoked_by` / `revoke_reason` populated. After
   * revocation, subsequent verify calls return `410 PERMIT_REVOKED`.
   *
   * Idempotent on `409 permit_revoked` for already-revoked permits;
   * server returns the existing revoked row in that case.
   *
   * Throws {@link AtlaSentError} on `404` (permit not in calling org),
   * `409` (already in a terminal state), `410` (expired before revoke),
   * or `429` (rate limited).
   */
  async revokePermitById(
    permitId: string,
    input: RevokePermitByIdInput = {},
  ): Promise<RevokePermitByIdResponse> {
    if (!permitId) {
      throw new AtlaSentError("permitId is required", { code: "bad_request" });
    }
    const body: { reason?: string } = {};
    if (input.reason !== undefined) body.reason = input.reason;
    const { body: wire, rateLimit } = await this.post<PermitRecord>(
      `/v1/permits/${encodeURIComponent(permitId)}/revoke`,
      body,
    );
    return { permit: wire, rateLimit };
  }

  /**
   * Verify a permit through the canonical REST surface
   * (`POST /v1/permits/{permitId}/verify`).
   *
   * Returns the unified verification envelope (`valid`,
   * `verification_type: 'permit'`, `reason`, `verified_at`, `evidence`)
   * plus the full {@link PermitRecord} fields preserved at the top
   * level. The `valid` field is the contract — pin to it.
   *
   * A `valid: false` is **not** thrown when the server returns 200 with
   * a denial reason (matches the verify-shape unification on the wire);
   * it is thrown on 4xx (`404` not found, `410` expired/consumed).
   */
  async verifyPermitById(permitId: string): Promise<VerifyPermitByIdResponse> {
    if (!permitId) {
      throw new AtlaSentError("permitId is required", { code: "bad_request" });
    }
    const { body: wire, rateLimit } = await this.post<
      VerifyPermitByIdResponse & PermitRecord
    >(`/v1/permits/${encodeURIComponent(permitId)}/verify`, {});
    // Server returns the canonical envelope merged with the Permit row
    // (allOf in openapi). Pull out the legacy permit row into `permit`
    // for callers that want it as a sub-object too.
    const { valid, verification_type, reason, verified_at, evidence, ...row } =
      wire as VerifyPermitByIdResponse & PermitRecord;
    return {
      valid,
      verification_type,
      reason,
      verified_at,
      evidence,
      permit: row as PermitRecord,
      rateLimit,
    };
  }

  /**
   * Get a single permit's full lifecycle state.
   *
   * Calls `GET /v1/permits/{permitId}` (the canonical REST surface).
   * Returns `status`, all timestamps, `revoked_at` / `revoked_by` /
   * `revoke_reason` (when applicable), and the bound `payload_hash`
   * / `decision_id`.
   *
   * Operator-facing introspection — answers "what state is this permit
   * in, and why?" without reading audit logs.
   *
   * Throws {@link AtlaSentError} on `404` (permit not in calling org)
   * or `410` (expired before retrieval).
   */
  async getPermit(permitId: string): Promise<GetPermitResponse> {
    if (!permitId) {
      throw new AtlaSentError("permitId is required", { code: "bad_request" });
    }
    const { body: wire, rateLimit } = await this.get<PermitRecord>(
      `/v1/permits/${encodeURIComponent(permitId)}`,
    );
    return { permit: wire, rateLimit };
  }

  /**
   * Poll whether a permit is currently valid.
   *
   * Calls `GET /v1/permits/{permitId}/valid` — a lightweight read
   * returning only the status snapshot optimised for guard heartbeat
   * polling. Guards with `permitRevalidationIntervalMs` set race this
   * against `tool.execute()` and throw {@link PermitRevoked} when
   * `status === "revoked"` arrives.
   *
   * Throws {@link AtlaSentError} on transport / auth failures.
   */
  async checkPermitValid(permitId: string): Promise<PermitValidResponse> {
    if (!permitId) {
      throw new AtlaSentError("permitId is required", { code: "bad_request" });
    }
    const { body } = await this.get<PermitValidResponse>(
      `/v1/permits/${encodeURIComponent(permitId)}/valid`,
    );
    return body;
  }

  /**
   * List permits issued to the calling org, most-recently-issued first.
   *
   * Calls `GET /v1/permits` (the canonical REST surface). Cursor-paged.
   * Filters narrow on server side; pagination uses the `created_at`
   * timestamp opaquely (`nextCursor`).
   *
   * Designed for incident review, debugging, and compliance
   * reconstruction.
   */
  async listPermits(
    input: ListPermitsRequest = {},
  ): Promise<ListPermitsResponse> {
    const params = new URLSearchParams();
    if (input.status) params.set("status", input.status);
    if (input.actorId) params.set("actor_id", input.actorId);
    if (input.actionType) params.set("action_type", input.actionType);
    if (input.from) params.set("from", input.from);
    if (input.to) params.set("to", input.to);
    if (input.limit !== undefined) params.set("limit", String(input.limit));
    if (input.cursor) params.set("cursor", input.cursor);

    const { body: wire, rateLimit } = await this.get<{
      permits?: PermitRecord[];
      total?: number;
      next_cursor?: string;
    }>("/v1/permits", params);

    if (!Array.isArray(wire.permits)) {
      throw new AtlaSentError(
        "Malformed response from /v1/permits: missing `permits` array",
        { code: "bad_response" },
      );
    }
    const result: ListPermitsResponse = {
      permits: wire.permits,
      total: typeof wire.total === "number" ? wire.total : wire.permits.length,
      rateLimit,
    };
    if (wire.next_cursor !== undefined) result.nextCursor = wire.next_cursor;
    return result;
  }

  /**
   * Self-introspection: ask the server to describe the API key this
   * client was constructed with. Returns the key's ID, organization,
   * environment, scopes, IP allowlist, per-minute rate limit, the
   * client IP the server observed, and the expiry (if any).
   *
   * Never includes the raw key or its hash. Safe to surface in operator
   * dashboards. Useful for `IP_NOT_ALLOWED` debugging (the server tells
   * you exactly which IP it saw) and for proactive expiry warnings.
   *
   * Throws {@link AtlaSentError} on transport / auth failures — same
   * taxonomy as {@link AtlaSentClient.evaluate}.
   */
  async keySelf(): Promise<ApiKeySelfResponse> {
    const { body: wire, rateLimit } =
      await this.get<ApiKeySelfWire>("/v1-api-key-self");

    if (
      typeof wire.key_id !== "string" ||
      typeof wire.org_id !== "string"
    ) {
      throw new AtlaSentError(
        "Malformed response from /v1-api-key-self: missing `key_id` or `org_id`",
        { code: "bad_response" },
      );
    }

    return {
      keyId: wire.key_id,
      orgId: wire.org_id,
      environment: wire.environment,
      scopes: wire.scopes ?? [],
      allowedCidrs: wire.allowed_cidrs ?? null,
      rateLimitPerMinute: wire.rate_limit_per_minute,
      clientIp: wire.client_ip ?? null,
      expiresAt: wire.expires_at ?? null,
      rateLimit,
    };
  }

  /**
   * Resolve the compliance control catalog into live enforcement status
   * (`GET /v1-compliance-controls`). Each regulatory clause is mapped to
   * an AtlaSent enforcement primitive and resolved to a live status —
   * `enforced` / `partial` / `not_enforced` / `no_data` / `attested`.
   *
   * Pass `framework` to filter to one regime (e.g. `"cfr_part_11"`); omit
   * for every framework. `from` / `to` bound the window the live status
   * aggregates are computed over. The response is wire-identical with the
   * server (snake_case rows), with a camelCase summary/window surfaced.
   *
   * Read-only — requires the `compliance:read` scope. Throws
   * {@link AtlaSentError} on transport / auth failures.
   */
  async complianceControls(
    query: ComplianceControlsQuery = {},
  ): Promise<ComplianceControlsResponse> {
    const params = new URLSearchParams();
    if (query.framework) params.set("framework", query.framework);
    if (query.from) params.set("from", query.from);
    if (query.to) params.set("to", query.to);

    const { body: wire, rateLimit } = await this.get<ComplianceControlsWire>(
      "/v1-compliance-controls",
      params,
    );

    if (!Array.isArray(wire.controls) || typeof wire.generated_at !== "string") {
      throw new AtlaSentError(
        "Malformed response from /v1-compliance-controls: missing `controls` or `generated_at`",
        { code: "bad_response" },
      );
    }

    return {
      framework: wire.framework ?? null,
      window: {
        from: wire.window?.from ?? null,
        to: wire.window?.to ?? null,
      },
      generatedAt: wire.generated_at,
      summary: wire.summary,
      controls: wire.controls,
      truncated: wire.truncated ?? false,
      rateLimit,
    };
  }

  /**
   * Produce a signed, self-contained compliance evidence pack for one
   * regulatory framework (`GET /v1-compliance-evidence-pack`). The returned
   * `bundle` is hashable offline: recompute SHA-256 over it and compare to
   * `sha256`, then check `signature` against the trust root.
   *
   * `framework` is REQUIRED (the server rejects the call without it).
   * `from` / `to` bound the evaluation window. The `bundle` is wire-identical
   * with the server so it can be persisted to disk untouched.
   *
   * Read-only — requires the `compliance:read` scope. Throws
   * {@link AtlaSentError} on transport / auth failures.
   */
  async complianceEvidencePack(
    query: ComplianceEvidencePackQuery,
  ): Promise<ComplianceEvidencePackResponse> {
    if (!query || !query.framework) {
      throw new AtlaSentError("framework is required", { code: "bad_request" });
    }
    const params = new URLSearchParams();
    params.set("framework", query.framework);
    if (query.from) params.set("from", query.from);
    if (query.to) params.set("to", query.to);

    const { body: wire, rateLimit } =
      await this.get<ComplianceEvidencePackWire>(
        "/v1-compliance-evidence-pack",
        params,
      );

    if (
      typeof wire.sha256 !== "string" ||
      wire.bundle === null ||
      typeof wire.bundle !== "object"
    ) {
      throw new AtlaSentError(
        "Malformed response from /v1-compliance-evidence-pack: missing `sha256` or `bundle`",
        { code: "bad_response" },
      );
    }

    return {
      framework: wire.framework,
      window: {
        from: wire.window?.from ?? null,
        to: wire.window?.to ?? null,
      },
      generatedAt: wire.generated_at,
      summary: wire.summary,
      sha256: wire.sha256,
      signature: wire.signature,
      signingStatus: wire.signing_status,
      keyId: wire.key_id ?? null,
      bundle: wire.bundle,
      rateLimit,
    };
  }

  /**
   * List persisted audit events for the authenticated organization
   * (`GET /v1-audit/events`). Returned rows are wire-identical with
   * the server: snake_case field names, including `previous_hash` and
   * the `hash` chain, so the response can be fed straight into the
   * offline verifier when paired with a signed export.
   *
   * `query.types` is a comma-joined list (e.g.
   * `"evaluate.allow,policy.updated"`). `cursor` is the opaque
   * `next_cursor` from the prior page. All fields are optional; the
   * server defaults `limit` to 50 (capped at 500).
   *
   * Throws {@link AtlaSentError} on transport / auth failures — same
   * taxonomy as {@link AtlaSentClient.evaluate}.
   */
  async listAuditEvents(
    query: AuditEventsQuery = {},
  ): Promise<AuditEventsResult> {
    const { body: wire, rateLimit } = await this.get<AuditEventsPage>(
      "/v1-audit/events",
      buildAuditEventsQuery(query),
    );

    if (!Array.isArray(wire.events) || typeof wire.total !== "number") {
      throw new AtlaSentError(
        "Malformed response from /v1-audit/events: missing `events` or `total`",
        { code: "bad_response" },
      );
    }

    return { ...wire, rateLimit };
  }

  /**
   * Request a signed audit export bundle
   * (`POST /v1-audit/exports`). The returned object is wire-identical
   * with the server — `signature`, `chain_head_hash`, `events`, and
   * friends survive untouched so the bundle can be persisted to disk
   * and handed to the offline verifier (`verifyBundle` /
   * `verifyAuditBundle`) without any reshaping.
   *
   * Pass `filter.types`, `filter.from`, `filter.to`, or `filter.actor_id`
   * to narrow the export; omit for a full-org bundle. `rateLimit` is
   * attached alongside the wire fields for observability.
   *
   * Throws {@link AtlaSentError} on transport / auth failures — same
   * taxonomy as {@link AtlaSentClient.evaluate}.
   */
  async createAuditExport(
    filter: AuditExportRequest = {},
  ): Promise<AuditExportResult> {
    const { body: wire, rateLimit } = await this.post<AuditExport>(
      "/v1-audit/exports",
      filter,
    );

    if (
      typeof wire.export_id !== "string" ||
      typeof wire.chain_head_hash !== "string" ||
      !Array.isArray(wire.events)
    ) {
      throw new AtlaSentError(
        "Malformed response from /v1-audit/exports: missing `export_id`, `chain_head_hash`, or `events`",
        { code: "bad_response" },
      );
    }

    return { ...wire, rateLimit };
  }

  /**
   * Re-evaluate a recorded decision against its originally-pinned policy
   * bundle and engine version, and report whether the result agrees with
   * what was recorded.
   *
   * Wraps `POST /v1-decisions-replay/:id/replay`. **Side-effect-free** — no
   * audit chain row is written and no permit is issued (per ADR-016).
   * Useful for compliance review, regression testing of bundle changes,
   * and post-incident investigation.
   *
   * Outcomes encoded in the response:
   * - `variance: "NONE"` — replay agrees with the original decision.
   * - `variance: "DECISION_CHANGED"` — same envelope, same bundle, different
   *   decision. Almost always indicates non-determinism in a rule
   *   (e.g. wall-clock comparison) and warrants investigation.
   * - `variance: "ENVELOPE_DRIFT"` — the recorded request envelope no longer
   *   hashes to the recorded value. The replay short-circuits without
   *   running the engine; `replay_decision` is absent. Treat as evidence
   *   of substrate tamper or a recorder bug.
   *
   * Server-side 409 responses (replay refused because the engine version
   * does not accept replay, or because no bundle was pinned) surface as
   * `AtlaSentError` with `code: "replay_not_eligible"` — callers should
   * treat them as expected for old / un-pinned decisions, not as bugs.
   *
   * Requires the `evaluate:write` API key scope.
   *
   * @param decisionId The UUID of the recorded decision to replay.
   *                   Matches `execution_evaluations.request_id`.
   *
   * @example
   * ```ts
   * const result = await client.replayDecision("dec_abc123");
   * if (result.variance === "DECISION_CHANGED") {
   *   console.warn(
   *     `Decision ${result.decision_id} changed on replay: ` +
   *     `${result.original_decision} → ${result.replay_decision}`,
   *   );
   * }
   * ```
   */
  async replayDecision(
    decisionId: string,
  ): Promise<ReplayDecisionResponse & { rateLimit: RateLimitState | null }> {
    if (typeof decisionId !== "string" || decisionId.length === 0) {
      throw new AtlaSentError("decisionId is required", {
        code: "bad_request",
      });
    }

    const path = `/v1-decisions-replay/${encodeURIComponent(decisionId)}/replay`;
    const { body: wire, rateLimit } = await this.post<ReplayDecisionResponse>(
      path,
      {},
    );

    // Defensive validation. The replay endpoint is alpha (see
    // STABLE_V2_PROMOTION.md) — wire shapes can shift without a
    // deprecation cycle, so guard the contract fields callers will
    // branch on rather than trusting the cast.
    if (
      typeof wire.decision_id !== "string" ||
      typeof wire.original_decision !== "string" ||
      typeof wire.engine_version_kind !== "string" ||
      typeof wire.accepts_replay !== "boolean" ||
      typeof wire.variance !== "string" ||
      typeof wire.envelope_verification !== "string" ||
      typeof wire.replayed_at !== "string"
    ) {
      throw new AtlaSentError(
        "Malformed response from /v1-decisions-replay/:id/replay: missing required fields",
        { code: "bad_response" },
      );
    }

    return { ...wire, rateLimit };
  }

  /**
   * ADR-015 Phase C — SDK-canonical replay runtime.
   *
   * Re-evaluates a recorded decision against its originally-pinned policy
   * bundle and engine version via `POST /v1/decisions/:id/replay`.
   * Side-effect-free server-side: no audit chain row is written and no
   * permit is issued (ADR-016 `mode: "replay"` sentinel).
   *
   * Differences from {@link replayDecision} (the 2.7.0 raw-wire surface):
   *
   * | | `replayDecision()` | `replay()` |
   * | --- | --- | --- |
   * | Path | `/v1-decisions-replay/:id/replay` | `/v1/decisions/:id/replay` |
   * | Variance | raw wire (`DECISION_CHANGED`) | SDK-canonical (`POLICY_DRIFT`) |
   * | 409 handling | throws `AtlaSentError` | returns `ENGINE_DRIFT` / `BUNDLE_MISSING` |
   * | Input shape | `decisionId: string` | `{ evaluationId }` |
   *
   * **Never throws on `409 replay_not_eligible`** — instead returns a
   * `ReplayResponse` with `varianceKind: "ENGINE_DRIFT"` (engine retired
   * beyond archival window) or `"BUNDLE_MISSING"` (no bundle pinned on
   * the original evaluation). Callers can always `switch` on
   * `result.varianceKind` without a try/catch.
   *
   * Fix-forward note: this method was originally landed in PR #275 but
   * dropped from the squash merge. The TS types (`ReplayResponse`,
   * `ReplayRequest`) and CHANGELOG made it through; the method itself
   * did not. Restored here to match the Python {@link
   * AtlaSentClient}.replay() that landed in atlasent-sdk@2.6.0 (Python).
   */
  async replay(input: ReplayRequest): Promise<ReplayResponse> {
    if (!input || typeof input.evaluationId !== "string" || input.evaluationId.length === 0) {
      throw new AtlaSentError("evaluationId is required", {
        code: "bad_request",
      });
    }

    const path = `/v1/decisions/${encodeURIComponent(input.evaluationId)}/replay`;
    let wire: Record<string, unknown>;
    let rateLimit: RateLimitState | null;
    try {
      const result = await this.post<Record<string, unknown>>(path, {});
      wire = result.body;
      rateLimit = result.rateLimit;
    } catch (err) {
      if (err instanceof AtlaSentError && err.status === 409) {
        const msg = (err.message ?? "").toLowerCase();
        const varianceKind: ReplayVarianceKind = msg.includes("bundle")
          ? "BUNDLE_MISSING"
          : "ENGINE_DRIFT";
        return {
          decisionId: input.evaluationId,
          varianceKind,
          originalDecision: "deny",
          acceptsReplay: false,
          replayedAt: new Date().toISOString(),
          rateLimit: null,
        };
      }
      throw err;
    }

    // Map raw wire variance → SDK-canonical. Unknown values default to
    // NONE per the additive-contract policy (the SDK never breaks on a
    // forward-introduced wire kind).
    const VARIANCE_MAP: Record<string, ReplayVarianceKind> = {
      NONE: "NONE",
      DECISION_CHANGED: "POLICY_DRIFT",
      ENVELOPE_DRIFT: "ENVELOPE_DRIFT",
      CHAIN_TAMPER: "CHAIN_TAMPER",
      BUNDLE_MISSING: "BUNDLE_MISSING",
      ENGINE_DRIFT: "ENGINE_DRIFT",
    };
    const rawVariance = typeof wire.variance === "string" ? wire.variance : "";
    const varianceKind: ReplayVarianceKind = VARIANCE_MAP[rawVariance] ?? "NONE";

    const replayDec = typeof wire.replay_decision === "string"
      ? (wire.replay_decision.toLowerCase() as DecisionCanonical)
      : undefined;
    const originalDec = (
      typeof wire.original_decision === "string"
        ? wire.original_decision.toLowerCase()
        : "deny"
    ) as DecisionCanonical;

    const response: ReplayResponse = {
      decisionId: typeof wire.decision_id === "string" ? wire.decision_id : input.evaluationId,
      varianceKind,
      originalDecision: originalDec,
      acceptsReplay: typeof wire.accepts_replay === "boolean" ? wire.accepts_replay : true,
      replayedAt: typeof wire.replayed_at === "string" ? wire.replayed_at : new Date().toISOString(),
      rateLimit,
    };
    if (typeof wire.original_deny_code === "string") response.originalDenyCode = wire.original_deny_code;
    if (replayDec !== undefined) response.replayedDecision = replayDec;
    if (typeof wire.replay_deny_code === "string") response.replayedDenyCode = wire.replay_deny_code;
    if (typeof wire.engine_version === "string") response.engineVersion = wire.engine_version;
    if (typeof wire.engine_version_kind === "string") response.engineVersionKind = wire.engine_version_kind;
    if (typeof wire.envelope_verification === "string") response.envelopeVerification = wire.envelope_verification;
    return response;
  }

  /**
  * Open a streaming evaluation session against `POST /v1/evaluate/stream`
  * (with fallback to `POST /v1-evaluate-stream` on older runtimes).
   *
   * Wire contract (V2-D4, `atlasent-api`
   * `supabase/functions/v1-evaluate-stream/handler.ts`): the endpoint is
   * body-compatible with `/v1/evaluate/batch` — a single-item
   * `{items: [{action_type, actor_id, context}]}` array, NOT a flat
   * `{action, agent, context, api_key}` body. Auth rides the `Authorization`
   * header (below), never a body `api_key` field. See {@link authorizeStream}
   * in `./v2.js` for the canonical reference implementation of this same
   * contract.
   *
   * Yields {@link StreamDecisionEvent} and {@link StreamProgressEvent} objects
   * as the server emits them. The iterator ends cleanly when the server sends
   * the real terminal `event: complete` frame (`{batch_id, count, partial}`)
   * or the legacy/generic `event: done`; it throws {@link AtlaSentError} on
   * transport errors or when the server sends `event: error`.
   *
   * The final {@link StreamDecisionEvent} (isFinal: true) carries a `permitId`
   * suitable for passing to {@link verifyPermit} after the stream closes.
   * `permitId` prefers the canonical `permit_token` field over the legacy
   * `decision_id` when both are present.
   *
   * Hardening:
   * - Throws {@link StreamTimeoutError} when no event arrives within
   *   `opts.timeoutMs` (default 30 s). Pass `0` to disable.
   * - Retries up to `opts.maxRetries` times (default 3) with 1 s / 2 s / 4 s
   *   delays on network drop (before a terminal event). Sends `Last-Event-ID`
   *   on reconnect when the server has emitted event IDs.
   * - Throws {@link StreamParseError} on partial / malformed JSON rather than
   *   crashing with a raw `SyntaxError`.
   * - Closes cleanly on `event: complete`, `event: done`, or a decision event
   *   with `done: true`.
   *
   * ```ts
   * for await (const event of client.protectStream({ agent, action })) {
   *   if (event.type === "decision" && event.isFinal) {
   *     await client.verifyPermit({ permitId: event.permitId });
   *   }
   * }
   * ```
   */
  async *protectStream(
    input: EvaluateRequest,
    opts: StreamOptions = {},
  ): AsyncIterable<StreamEvent> {
    const streamTimeoutMs = opts.timeoutMs ?? 30_000;
    const maxRetries = opts.maxRetries ?? 3;

    // Accept both the canonical {action_type, actor_id} and the legacy
    // {action, agent} input shape, matching evaluate()/evaluateMany(). The
    // real /v1-evaluate-stream handler is body-compatible with
    // /v1/evaluate/batch: {items: [{action_type, actor_id, context, ...}]} —
    // a single-item array, not a flat body. `api_key` never rides the body;
    // auth is carried by the Authorization header set below, same as every
    // other call path in this SDK.
    const { action_type, actor_id } = resolveEvaluateIdentity(
      input as LegacyEvaluateRequest | V2EvaluateRequest,
    );
    const body = {
      items: [
        {
          action_type,
          actor_id,
          context: input.context ?? {},
        },
      ],
    };

    const requestId = globalThis.crypto.randomUUID();
    let streamPath = V1_EVALUATE_STREAM_PATH;

    let lastEventId: string | undefined;
    let retryCount = 0;

    while (true) {
      const headers: Record<string, string> = {
        Accept: "text/event-stream",
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
        "User-Agent": this.userAgent,
        ...this.regionHeaders,
        // ADR-025: wire-protocol version declared on every request.
        "X-AtlaSent-Protocol-Version": "1",
        "X-Request-ID": requestId,
      };
      if (lastEventId !== undefined) {
        headers["Last-Event-ID"] = lastEventId;
      }

      const connectionTimeoutSignal = AbortSignal.timeout(this.timeoutMs);
      const signal = opts.signal
        ? (
            AbortSignal as unknown as { any(s: AbortSignal[]): AbortSignal }
          ).any([connectionTimeoutSignal, opts.signal])
        : connectionTimeoutSignal;

      let response: Response;
      try {
        response = await this.fetchImpl(`${this.baseUrl}${streamPath}`, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
          signal,
        });
      } catch (err) {
        const mapped = mapFetchError(err, requestId);
        if (mapped.code === "network" && retryCount < maxRetries) {
          retryCount++;
          await sleep(1_000 * Math.pow(2, retryCount - 1)); // 1s, 2s, 4s
          continue;
        }
        throw mapped;
      }

      if (!response.ok) {
        if (
          streamPath === V1_EVALUATE_STREAM_PATH &&
          (response.status === 404 || response.status === 405)
        ) {
          streamPath = V1_EVALUATE_STREAM_LEGACY_PATH;
          continue;
        }
        throw await buildHttpError(response, requestId);
      }

      if (!response.body) {
        throw new AtlaSentError("Expected streaming body from AtlaSent API", {
          code: "bad_response",
          status: response.status,
          requestId,
        });
      }

      let streamDone = false;
      let networkDrop = false;

      try {
        for await (const event of parseSseStream(
          response.body,
          requestId,
          streamTimeoutMs,
          (id) => {
            lastEventId = id;
          },
        )) {
          yield event;
          if (event.type === "decision" && event.isFinal) {
            streamDone = true;
          }
        }
        // parseSseStream returned normally (saw event: done or stream ended)
        streamDone = true;
      } catch (err) {
        if (err instanceof AtlaSentError && err.code === "network") {
          networkDrop = true;
        } else {
          throw err;
        }
      }

      if (streamDone) break;

      // Network drop before terminal event — attempt reconnect
      if (networkDrop && retryCount < maxRetries) {
        retryCount++;
        await sleep(1_000 * Math.pow(2, retryCount - 1)); // 1s, 2s, 4s
        continue;
      }
      if (networkDrop) {
        throw new AtlaSentError(
          `AtlaSent stream dropped after ${retryCount} reconnection attempts`,
          { code: "network", requestId },
        );
      }
      break;
    }
  }

  // ── License verification (self-hosted / air-gapped) ──────────────────────

  /**
   * Retrieve the license status of this self-hosted or air-gapped deployment.
   *
   * Calls `GET /v1/license`. Returns the current validity state, expiry,
   * enabled feature flags, and optional capacity limits for the installed
   * license key.
   *
   * Callers should check `result.status === "active"` before proceeding.
   * A `"grace"` status means the license has lapsed but a grace window
   * (`grace_until`) is still open — the deployment continues to function
   * but the license should be renewed immediately.
   *
   * Throws {@link AtlaSentError} on transport / auth failures.
   */
  async getLicense(): Promise<LicenseStatus & { rateLimit: RateLimitState | null }> {
    const { body, rateLimit } = await this.get<LicenseStatus>("/v1/license");
    return { ...body, rateLimit };
  }

  /**
   * Validate a signed license blob against this deployment's installed
   * public key.
   *
   * Calls `POST /v1/license/verify`. Use this when onboarding a new license
   * key or rotating an expiring one — submit the blob received from AtlaSent
   * and check `result.valid` before applying the new license.
   *
   * A `valid: false` response is **not** thrown — inspect the returned
   * object. Only transport / server errors throw {@link AtlaSentError}.
   *
   * @param blob — The signed license blob string provided by AtlaSent.
   */
  async verifyLicense(
    blob: string,
  ): Promise<LicenseVerifyResult & { rateLimit: RateLimitState | null }> {
    if (!blob || typeof blob !== "string") {
      throw new AtlaSentError("blob is required", { code: "bad_request" });
    }
    const { body, rateLimit } = await this.post<LicenseVerifyResult>(
      "/v1/license/verify",
      { blob },
    );
    return { ...body, rateLimit };
  }

  private async post<T>(
    path: string,
    body: unknown,
    query?: URLSearchParams,
  ): Promise<{ body: T; rateLimit: RateLimitState | null }> {
    return this.request<T>(path, "POST", body, query);
  }

  private async postWithPathFallback<T>(
    primaryPath: string,
    fallbackPath: string,
    body: unknown,
    query?: URLSearchParams,
  ): Promise<{ body: T; rateLimit: RateLimitState | null }> {
    try {
      return await this.post<T>(primaryPath, body, query);
    } catch (err) {
      if (
        err instanceof AtlaSentError &&
        (err.status === 404 || err.status === 405)
      ) {
        return this.post<T>(fallbackPath, body, query);
      }
      throw err;
    }
  }

  private async get<T>(
    path: string,
    query?: URLSearchParams,
  ): Promise<{ body: T; rateLimit: RateLimitState | null }> {
    return this.request<T>(path, "GET", undefined, query);
  }

  private async request<T>(
    path: string,
    method: "GET" | "POST",
    body: unknown,
    query: URLSearchParams | undefined,
  ): Promise<{ body: T; rateLimit: RateLimitState | null }> {
    const qs =
      query && Array.from(query).length > 0 ? `?${query.toString()}` : "";
    const url = `${this.baseUrl}${path}${qs}`;
    const requestId = globalThis.crypto.randomUUID();

    /**
     * Canonical auth header. The API also accepts X-AtlaSent-Key for legacy
     * compatibility but that path is deprecated and will be removed in a future
     * version. Always use Authorization: Bearer <api_key>.
     */
    const headers: Record<string, string> = {
      Accept: "application/json",
      Authorization: `Bearer ${this.apiKey}`,
      "User-Agent": this.userAgent,
      ...this.regionHeaders,
      "X-Request-ID": requestId,
      // ADR-025: wire-protocol version declared on every request.
      "X-AtlaSent-Protocol-Version": "1",
    };
    if (method === "POST") headers["Content-Type"] = "application/json";

    const bodyStr = method === "POST" ? JSON.stringify(body) : undefined;

    for (let attempt = 0; ; attempt++) {
      const init: RequestInit = {
        method,
        headers,
        signal: AbortSignal.timeout(this.timeoutMs),
      };
      if (bodyStr !== undefined) init.body = bodyStr;

      let response: Response;
      try {
        response = await this.fetchImpl(url, init);
      } catch (err) {
        const mapped = mapFetchError(err, requestId);
        if (isRetryable(mapped) && hasAttemptsLeft(attempt, this.retryPolicy)) {
          await sleep(computeBackoffMs(attempt, this.retryPolicy, mapped));
          continue;
        }
        throw mapped;
      }

      if (!response.ok) {
        const httpErr = await buildHttpError(response, requestId);
        if (
          isRetryable(httpErr) &&
          hasAttemptsLeft(attempt, this.retryPolicy)
        ) {
          await sleep(computeBackoffMs(attempt, this.retryPolicy, httpErr));
          continue;
        }
        throw httpErr;
      }

      let parsed: unknown;
      try {
        parsed = await response.json();
      } catch (err) {
        const jsonErr = new AtlaSentError(
          "Invalid JSON response from AtlaSent API",
          {
            code: "bad_response",
            status: response.status,
            requestId,
            cause: err,
          },
        );
        if (
          isRetryable(jsonErr) &&
          hasAttemptsLeft(attempt, this.retryPolicy)
        ) {
          await sleep(computeBackoffMs(attempt, this.retryPolicy, jsonErr));
          continue;
        }
        throw jsonErr;
      }

      if (parsed === null || typeof parsed !== "object") {
        const shapeErr = new AtlaSentError(
          "Expected a JSON object from AtlaSent API",
          {
            code: "bad_response",
            status: response.status,
            requestId,
          },
        );
        if (
          isRetryable(shapeErr) &&
          hasAttemptsLeft(attempt, this.retryPolicy)
        ) {
          await sleep(computeBackoffMs(attempt, this.retryPolicy, shapeErr));
          continue;
        }
        throw shapeErr;
      }

      return {
        body: parsed as T,
        rateLimit: parseRateLimitHeaders(response.headers),
      };
    }
  }

  /**
   * Open a new HITL escalation. Bridges a `hold` outcome from
   * `protect()` to the approval queue: an agent that receives a
   * `hold` decision calls this to enroll the proposed action for
   * human review. The returned escalation can then be polled with
   * `getHitlEscalation()` or driven to terminal by
   * `approveHitlEscalation()` / `rejectHitlEscalation()`.
   *
   * Quorum, pool size, fallback decision and routing inherit from
   * the server-side policy when omitted from `input`.
   *
   * Calls `POST /v1/hitl`.
   */
  async createHitlEscalation(
    input: HitlCreateRequest,
  ): Promise<{ escalation: HitlEscalation; rateLimit: RateLimitState | null }> {
    const { body, rateLimit } = await this.post<HitlEscalation>(
      "/v1/hitl",
      input,
    );
    return { escalation: body, rateLimit };
  }

  /**
   * List HITL escalations for the calling org. Defaults to
   * `status=pending`; pass `status` to query other queues
   * (`escalated`, `approved`, `rejected`, `auto_approved`,
   * `timed_out`).
   *
   * Calls `GET /v1/hitl`.
   */
  async listHitlEscalations(input: ListHitlEscalationsRequest = {}): Promise<{
    data: ListHitlEscalationsResponse;
    rateLimit: RateLimitState | null;
  }> {
    const params = new URLSearchParams();
    if (input.status) params.set("status", input.status);
    if (input.agentId) params.set("agent_id", input.agentId);
    if (input.assignedToUserId)
      params.set("assigned_to_user_id", input.assignedToUserId);
    if (input.limit !== undefined) params.set("limit", String(input.limit));
    if (input.cursor) params.set("cursor", input.cursor);
    const { body, rateLimit } = await this.get<ListHitlEscalationsResponse>(
      "/v1/hitl",
      params,
    );
    return { data: body, rateLimit };
  }

  /**
   * Get a HITL escalation. The server payload includes a live
   * `quorum_progress` snapshot when the escalation is still open.
   *
   * Calls `GET /v1/hitl/:id`.
   */
  async getHitlEscalation(
    escalationId: string,
  ): Promise<{ escalation: HitlEscalation; rateLimit: RateLimitState | null }> {
    if (!escalationId) {
      throw new AtlaSentError("escalationId is required", {
        code: "bad_request",
      });
    }
    const { body, rateLimit } = await this.get<HitlEscalation>(
      `/v1/hitl/${encodeURIComponent(escalationId)}`,
    );
    return { escalation: body, rateLimit };
  }

  /**
   * List per-approver vote rows for an escalation.
   * Calls `GET /v1/hitl/:id/approvals`.
   */
  async listHitlApprovals(escalationId: string): Promise<{
    approvals: HitlApprovalRecord[];
    rateLimit: RateLimitState | null;
  }> {
    const { body, rateLimit } = await this.get<{
      approvals: HitlApprovalRecord[];
    }>(`/v1/hitl/${encodeURIComponent(escalationId)}/approvals`);
    return { approvals: body.approvals ?? [], rateLimit };
  }

  /**
   * List the escalation chain hops for an escalation. Each `/escalate`
   * call appends one row.
   * Calls `GET /v1/hitl/:id/chain`.
   */
  async getHitlChain(
    escalationId: string,
  ): Promise<{ chain: HitlChainHop[]; rateLimit: RateLimitState | null }> {
    const { body, rateLimit } = await this.get<{ chain: HitlChainHop[] }>(
      `/v1/hitl/${encodeURIComponent(escalationId)}/chain`,
    );
    return { chain: body.chain ?? [], rateLimit };
  }

  /**
   * Record an approve vote. Resolves the escalation only once the
   * server-side quorum count is satisfied; before that the response
   * carries a refreshed escalation row with the latest
   * `quorum_progress`.
   *
   * Calls `POST /v1/hitl/:id/approve`. The server returns 409
   * `duplicate_vote` if the same principal has already voted, and
   * 409 `already_rejected` if a concurrent reject crossed the line.
   */
  async approveHitlEscalation(
    escalationId: string,
    input: HitlApproveRequest = {},
  ): Promise<{ escalation: HitlEscalation; rateLimit: RateLimitState | null }> {
    const { body, rateLimit } = await this.post<HitlEscalation>(
      `/v1/hitl/${encodeURIComponent(escalationId)}/approve`,
      input,
    );
    return { escalation: body, rateLimit };
  }

  /**
   * Record a reject vote. Reject is short-circuit terminal — a single
   * reject closes the escalation regardless of how many approves have
   * accumulated.
   *
   * Calls `POST /v1/hitl/:id/reject`.
   */
  async rejectHitlEscalation(
    escalationId: string,
    input: HitlRejectRequest = {},
  ): Promise<{ escalation: HitlEscalation; rateLimit: RateLimitState | null }> {
    const { body, rateLimit } = await this.post<HitlEscalation>(
      `/v1/hitl/${encodeURIComponent(escalationId)}/reject`,
      input,
    );
    return { escalation: body, rateLimit };
  }

  /**
   * Re-route an open escalation to a higher tier. Bounded by the
   * escalation's `max_escalation_depth` — the server returns 409
   * `chain_exhausted` and applies the configured fallback decision
   * once the ceiling is hit.
   *
   * Calls `POST /v1/hitl/:id/escalate`.
   */
  async escalateHitlEscalation(
    escalationId: string,
    input: HitlEscalateRequest,
  ): Promise<{ escalation: HitlEscalation; rateLimit: RateLimitState | null }> {
    const { body, rateLimit } = await this.post<HitlEscalation>(
      `/v1/hitl/${encodeURIComponent(escalationId)}/escalate`,
      input,
    );
    return { escalation: body, rateLimit };
  }

  /**
   * Manually apply the escalation's `fallback_decision`. Useful for
   * admin recovery of a hung escalation when the cron sweeper hasn't
   * run yet, or to short-circuit a stuck flow during incident
   * response.
   *
   * Calls `POST /v1/hitl/:id/timeout`.
   */
  async timeoutHitlEscalation(
    escalationId: string,
  ): Promise<{ escalation: HitlEscalation; rateLimit: RateLimitState | null }> {
    const { body, rateLimit } = await this.post<HitlEscalation>(
      `/v1/hitl/${encodeURIComponent(escalationId)}/timeout`,
      {},
    );
    return { escalation: body, rateLimit };
  }

  /**
   * Run a named governance graph traversal query.
   *
   * Dispatches to `GET /v1/governance/graph/query?type=<queryType>`.
   * Each query type returns a different row shape — the return type
   * narrows automatically based on the literal `queryType` argument.
   *
   * `"user_approvals"` requires `params.actor_id` — the server returns
   * a 400 if it is absent.
   */
  async queryGovernanceGraph<T extends GovernanceGraphQueryType>(
    queryType: T,
    params: GovernanceGraphQueryParams = {},
  ): Promise<GovernanceGraphQueryResponse<T>> {
    const qs = new URLSearchParams({ type: queryType });
    if (params.actor_id) qs.set("actor_id", params.actor_id);
    const { body, rateLimit } = await this.get<{
      query_type: T;
      results: GovernanceGraphResultRow<T>[];
      org_id: string;
    }>("/v1/governance/graph/query", qs);
    return { ...body, rateLimit };
  }

  /**
   * Reconstruct the multi-system execution timeline for a specific incident.
   *
   * Calls `GET /v1/governance/timeline/incident/{incidentId}`. Backed
   * server-side by `reconstruct_incident_chains_v2()`, which fixes the
   * `executor_id → actor_id` bug that silently produced empty timelines
   * in the original function.
   *
   * Returns full execution rows including the §13.1 columns
   * (`delegation_chain_id`, `replay_of_execution_id`, `incident_id`,
   * `policy_version_id`, `bundle_version_id`) alongside the actor
   * timeline and evidence rows.
   */
  async getIncidentTimeline(
    incidentId: string,
  ): Promise<IncidentTimelineResponse> {
    if (!incidentId) {
      throw new AtlaSentError("incidentId is required", {
        code: "bad_request",
      });
    }
    const { body, rateLimit } = await this.get<
      Omit<IncidentTimelineResponse, "rateLimit">
    >(`/v1/governance/timeline/incident/${encodeURIComponent(incidentId)}`);
    return { ...body, rateLimit };
  }

  // ── Authority Intelligence ────────────────────────────────────────────────

  /**
   * Explain why (or why not) a principal currently has authority for a
   * scope in the caller's org — "why may principal P exercise
   * scope/action A in organization O right now?"
   *
   * Calls `GET /v1-authority-intelligence/explain-authority`. Strictly
   * read-only and additive: it explains the same facts `/v1-evaluate`
   * and `/v1-verify-permit` already read, and never changes any
   * deny/hold/allow semantics. Returned verbatim from the server — the
   * SDK performs no interpretation of `paths` / `unresolved` /
   * `authority_found` beyond parsing the JSON response.
   *
   * Requires the `authority_intelligence:read` API key scope.
   */
  async explainAuthority(params: {
    principalId: string;
    requestedScope: string;
    resourceId?: string;
  }): Promise<ExplainAuthorityResult> {
    if (!params.principalId) {
      throw new AtlaSentError("principalId is required", {
        code: "bad_request",
      });
    }
    if (!params.requestedScope) {
      throw new AtlaSentError("requestedScope is required", {
        code: "bad_request",
      });
    }
    const qs = new URLSearchParams({
      principal_id: params.principalId,
      requested_scope: params.requestedScope,
    });
    if (params.resourceId) qs.set("resource_id", params.resourceId);
    const { body } = await this.get<ExplainAuthorityResult>(
      "/v1-authority-intelligence/explain-authority",
      qs,
    );
    return body;
  }

  // ── Connector Management ─────────────────────────────────────────────────

  /**
   * List connectors registered for the calling org.
   * Calls `GET /v1/governance/connectors`.
   */
  async listConnectors(
    options: { cursor?: string; limit?: number } = {},
  ): Promise<ListConnectorsResponse> {
    const params = new URLSearchParams();
    if (options.cursor) params.set("cursor", options.cursor);
    if (options.limit !== undefined) params.set("limit", String(options.limit));
    const { body, rateLimit } = await this.get<{
      connectors: ListConnectorsResponse["connectors"];
      total: number;
      next_cursor?: string;
    }>("/v1/governance/connectors", params);
    const result: ListConnectorsResponse = {
      connectors: body.connectors ?? [],
      total: body.total,
      rateLimit,
    };
    if (body.next_cursor) result.nextCursor = body.next_cursor;
    return result;
  }

  /**
   * Register and install a new connector for the calling org.
   * Calls `POST /v1/governance/connectors`.
   */
  async installConnector(
    input: InstallConnectorInput,
  ): Promise<InstallConnectorResponse> {
    const { body, rateLimit } = await this.post<
      InstallConnectorResponse["connector"]
    >("/v1/governance/connectors", input);
    return { connector: body, rateLimit };
  }

  /**
   * Store encrypted credentials for a connector.
   * Calls `POST /v1/governance/connectors/{id}/authenticate`.
   */
  async authenticateConnector(
    connectorId: string,
    input: AuthenticateConnectorInput,
  ): Promise<AuthenticateConnectorResponse> {
    if (!connectorId) {
      throw new AtlaSentError("connectorId is required", {
        code: "bad_request",
      });
    }
    const { body, rateLimit } = await this.post<{
      credential_id: string;
      version: number;
    }>(
      `/v1/governance/connectors/${encodeURIComponent(connectorId)}/authenticate`,
      input,
    );
    return {
      credential_id: body.credential_id,
      version: body.version,
      rateLimit,
    };
  }

  /**
   * Trigger an incremental sync for a connector.
   * Calls `POST /v1/governance/connectors/{id}/sync`.
   */
  async syncConnector(connectorId: string): Promise<SyncConnectorResponse> {
    if (!connectorId) {
      throw new AtlaSentError("connectorId is required", {
        code: "bad_request",
      });
    }
    const { body, rateLimit } = await this.post<{
      connector_id: string;
      status: SyncConnectorResponse["status"];
      sync_started_at: string;
    }>(`/v1/governance/connectors/${encodeURIComponent(connectorId)}/sync`, {});
    return { ...body, rateLimit };
  }

  /**
   * Revoke a connector and all its associated credentials.
   * Calls `POST /v1/governance/connectors/{id}/revoke`.
   */
  async revokeConnector(
    connectorId: string,
    reason?: string,
  ): Promise<RevokeConnectorResponse> {
    if (!connectorId) {
      throw new AtlaSentError("connectorId is required", {
        code: "bad_request",
      });
    }
    const body: { reason?: string } = {};
    if (reason !== undefined) body.reason = reason;
    const { body: wire, rateLimit } = await this.post<{
      connector_id: string;
      revoked_at: string;
    }>(
      `/v1/governance/connectors/${encodeURIComponent(connectorId)}/revoke`,
      body,
    );
    return { ...wire, rateLimit };
  }

  /**
   * Rotate the credentials for a connector.
   * Calls `POST /v1/governance/connectors/{id}/rotate-credentials`.
   */
  async rotateConnectorCredentials(
    connectorId: string,
  ): Promise<RotateCredentialsResponse> {
    if (!connectorId) {
      throw new AtlaSentError("connectorId is required", {
        code: "bad_request",
      });
    }
    const { body, rateLimit } = await this.post<{
      connector_id: string;
      new_version: number;
      rotated_at: string;
    }>(
      `/v1/governance/connectors/${encodeURIComponent(connectorId)}/rotate-credentials`,
      {},
    );
    return { ...body, rateLimit };
  }

  /**
   * List enforcement policies for the calling org, optionally filtered by connector type.
   * Calls `GET /v1/governance/enforcement-policies`.
   */
  async listEnforcementPolicies(
    connectorType?: ConnectorType,
  ): Promise<ListEnforcementPoliciesResponse> {
    const params = new URLSearchParams();
    if (connectorType) params.set("connector_type", connectorType);
    const { body, rateLimit } = await this.get<{
      policies: ListEnforcementPoliciesResponse["policies"];
      total: number;
    }>("/v1/governance/enforcement-policies", params);
    return { policies: body.policies ?? [], total: body.total, rateLimit };
  }

  /**
   * Create or update a connector enforcement policy.
   * Calls `POST /v1/governance/enforcement-policies`.
   */
  async upsertEnforcementPolicy(
    input: UpsertEnforcementPolicyInput,
  ): Promise<UpsertEnforcementPolicyResponse> {
    const { body, rateLimit } = await this.post<
      UpsertEnforcementPolicyResponse["policy"]
    >("/v1/governance/enforcement-policies", input);
    return { policy: body, rateLimit };
  }

  // ── Organizational Risk Graph ─────────────────────────────────────────────

  /**
   * Trigger a fresh org-level risk score computation.
   * Calls `POST /v1/governance/risk/compute`.
   */
  async computeOrgRisk(
    options: ComputeOrgRiskOptions = {},
  ): Promise<ComputeOrgRiskResponse> {
    const { body, rateLimit } = await this.post<
      ComputeOrgRiskResponse["score"]
    >("/v1/governance/risk/compute", options);
    return { score: body, rateLimit };
  }

  /**
   * Retrieve the most recently computed risk score for the calling org.
   * Calls `GET /v1/governance/risk/latest`.
   */
  async getLatestOrgRisk(): Promise<GetLatestOrgRiskResponse> {
    const { body, rateLimit } = await this.get<{
      score: GetLatestOrgRiskResponse["score"];
    }>("/v1/governance/risk/latest");
    return { score: body.score ?? null, rateLimit };
  }

  /**
   * Page through historical org risk scores, most-recent first.
   * Calls `GET /v1/governance/risk/history`.
   */
  async listOrgRiskHistory(
    options: { cursor?: string; limit?: number } = {},
  ): Promise<ListOrgRiskHistoryResponse> {
    const params = new URLSearchParams();
    if (options.cursor) params.set("cursor", options.cursor);
    if (options.limit !== undefined) params.set("limit", String(options.limit));
    const { body, rateLimit } = await this.get<{
      scores: ListOrgRiskHistoryResponse["scores"];
      total: number;
      next_cursor?: string;
    }>("/v1/governance/risk/history", params);
    const result: ListOrgRiskHistoryResponse = {
      scores: body.scores ?? [],
      total: body.total,
      rateLimit,
    };
    if (body.next_cursor) result.nextCursor = body.next_cursor;
    return result;
  }
  // ── Cross-Org Permission Negotiation ──────────────────────────────────────

  async checkCrossOrgPermission(
    req: CrossOrgPermissionCheckRequest,
  ): Promise<CrossOrgPermissionCheckResult> {
    const { body } = await this.post<CrossOrgPermissionCheckResult>(
      "/v1/federation/permission-check",
      req,
    );
    return body;
  }

  async listCrossOrgPermissionChecks(
    params?: CrossOrgPermissionCheckListParams,
  ): Promise<CrossOrgPermissionCheckResult[]> {
    const qs = new URLSearchParams();
    if (params?.source_org_id) qs.set("source_org_id", params.source_org_id);
    if (params?.target_org_id) qs.set("target_org_id", params.target_org_id);
    if (params?.allowed !== undefined)
      qs.set("allowed", String(params.allowed));
    if (params?.limit !== undefined) qs.set("limit", String(params.limit));
    const { body } = await this.get<{
      checks: CrossOrgPermissionCheckResult[];
    }>("/v1/federation/permission-checks", qs);
    return body.checks ?? [];
  }

  // ── Anomaly Response Automation ───────────────────────────────────────────

  async listAnomalyResponseRules(): Promise<AnomalyResponseRule[]> {
    const { body } = await this.get<{ rules: AnomalyResponseRule[] }>(
      "/v1/anomaly-response/rules",
    );
    return body.rules ?? [];
  }

  async createAnomalyResponseRule(
    req: CreateAnomalyResponseRuleRequest,
  ): Promise<AnomalyResponseRule> {
    const { body } = await this.post<AnomalyResponseRule>(
      "/v1/anomaly-response/rules",
      req,
    );
    return body;
  }

  async updateAnomalyResponseRule(
    id: string,
    updates: Partial<CreateAnomalyResponseRuleRequest>,
  ): Promise<AnomalyResponseRule> {
    const { body } = await this.post<AnomalyResponseRule>(
      `/v1/anomaly-response/rules/${encodeURIComponent(id)}/update`,
      updates,
    );
    return body;
  }

  async deleteAnomalyResponseRule(id: string): Promise<void> {
    await this.post<Record<string, unknown>>(
      `/v1/anomaly-response/rules/${encodeURIComponent(id)}/delete`,
      {},
    );
  }

  async triggerAnomalyResponse(
    req: TriggerAnomalyResponseRequest,
  ): Promise<AnomalyResponseEvent[]> {
    const { body } = await this.post<{ events: AnomalyResponseEvent[] }>(
      "/v1/anomaly-response/trigger",
      req,
    );
    return body.events ?? [];
  }

  async listAnomalyResponseEvents(params?: {
    limit?: number;
    execution_id?: string;
  }): Promise<AnomalyResponseEvent[]> {
    const qs = new URLSearchParams();
    if (params?.execution_id) qs.set("execution_id", params.execution_id);
    if (params?.limit !== undefined) qs.set("limit", String(params.limit));
    const { body } = await this.get<{ events: AnomalyResponseEvent[] }>(
      "/v1/anomaly-response/events",
      qs,
    );
    return body.events ?? [];
  }

  // ── Budget Exception Workflows ────────────────────────────────────────────

  async listBudgetExceptions(params?: {
    status?: BudgetExceptionStatus;
    budget_policy_id?: string;
    limit?: number;
    offset?: number;
  }): Promise<BudgetExceptionRequest[]> {
    const qs = new URLSearchParams();
    if (params?.status) qs.set("status", params.status);
    if (params?.budget_policy_id)
      qs.set("budget_policy_id", params.budget_policy_id);
    if (params?.limit !== undefined) qs.set("limit", String(params.limit));
    if (params?.offset !== undefined) qs.set("offset", String(params.offset));
    const { body } = await this.get<{ exceptions: BudgetExceptionRequest[] }>(
      "/v1/budget-exceptions",
      qs,
    );
    return body.exceptions ?? [];
  }

  async getBudgetException(id: string): Promise<BudgetExceptionRequest> {
    const { body } = await this.get<BudgetExceptionRequest>(
      `/v1/budget-exceptions/${encodeURIComponent(id)}`,
    );
    return body;
  }

  async createBudgetException(
    req: CreateBudgetExceptionRequest,
  ): Promise<BudgetExceptionRequest> {
    const { body } = await this.post<BudgetExceptionRequest>(
      "/v1/budget-exceptions",
      req,
    );
    return body;
  }

  async approveBudgetException(
    id: string,
    req: ApproveBudgetExceptionRequest,
  ): Promise<BudgetExceptionRequest> {
    const { body } = await this.post<BudgetExceptionRequest>(
      `/v1/budget-exceptions/${encodeURIComponent(id)}/approve`,
      req,
    );
    return body;
  }

  async rejectBudgetException(
    id: string,
    review_notes?: string,
  ): Promise<BudgetExceptionRequest> {
    const { body } = await this.post<BudgetExceptionRequest>(
      `/v1/budget-exceptions/${encodeURIComponent(id)}/reject`,
      { review_notes },
    );
    return body;
  }

  async cancelBudgetException(id: string): Promise<BudgetExceptionRequest> {
    const { body } = await this.post<BudgetExceptionRequest>(
      `/v1/budget-exceptions/${encodeURIComponent(id)}/cancel`,
      {},
    );
    return body;
  }

  // ── Regulatory Escalation Chain ───────────────────────────────────────────

  async listRegulatoryAuthorityLevels(): Promise<RegulatoryAuthorityLevel[]> {
    const { body } = await this.get<{ levels: RegulatoryAuthorityLevel[] }>(
      "/v1/regulatory/authority-levels",
    );
    return body.levels ?? [];
  }

  async createRegulatoryAuthorityLevel(
    req: Omit<RegulatoryAuthorityLevel, "id" | "org_id" | "created_at">,
  ): Promise<RegulatoryAuthorityLevel> {
    const { body } = await this.post<RegulatoryAuthorityLevel>(
      "/v1/regulatory/authority-levels",
      req,
    );
    return body;
  }

  async listRegulatoryEscalations(params?: {
    status?: RegulatoryEscalationStatus;
    subject_type?: string;
    subject_id?: string;
  }): Promise<RegulatoryEscalation[]> {
    const qs = new URLSearchParams();
    if (params?.status) qs.set("status", params.status);
    if (params?.subject_type) qs.set("subject_type", params.subject_type);
    if (params?.subject_id) qs.set("subject_id", params.subject_id);
    const { body } = await this.get<{ escalations: RegulatoryEscalation[] }>(
      "/v1/regulatory/escalations",
      qs,
    );
    return body.escalations ?? [];
  }

  async createRegulatoryEscalation(
    req: CreateRegulatoryEscalationRequest,
  ): Promise<RegulatoryEscalation> {
    const { body } = await this.post<RegulatoryEscalation>(
      "/v1/regulatory/escalations",
      req,
    );
    return body;
  }

  async acknowledgeRegulatoryEscalation(
    id: string,
  ): Promise<RegulatoryEscalation> {
    const { body } = await this.post<RegulatoryEscalation>(
      `/v1/regulatory/escalations/${encodeURIComponent(id)}/acknowledge`,
      {},
    );
    return body;
  }

  async resolveRegulatoryEscalation(
    id: string,
    resolution: string,
    resolution_details?: Record<string, unknown>,
  ): Promise<RegulatoryEscalation> {
    const { body } = await this.post<RegulatoryEscalation>(
      `/v1/regulatory/escalations/${encodeURIComponent(id)}/resolve`,
      { resolution, resolution_details },
    );
    return body;
  }

  async overrideRegulatoryEscalation(
    id: string,
    reason: string,
  ): Promise<RegulatoryEscalation> {
    const { body } = await this.post<RegulatoryEscalation>(
      `/v1/regulatory/escalations/${encodeURIComponent(id)}/override`,
      { reason },
    );
    return body;
  }

  // ── Incentive Signal Feedback Loop ────────────────────────────────────────

  async listSignalActions(
    signal_id: string,
  ): Promise<GovernanceSignalAction[]> {
    const { body } = await this.get<{ actions: GovernanceSignalAction[] }>(
      `/v1/governance/signals/${encodeURIComponent(signal_id)}/actions`,
    );
    return body.actions ?? [];
  }

  async recordSignalAction(
    signal_id: string,
    req: RecordSignalActionRequest,
  ): Promise<GovernanceSignalAction> {
    const { body } = await this.post<GovernanceSignalAction>(
      `/v1/governance/signals/${encodeURIComponent(signal_id)}/actions`,
      req,
    );
    return body;
  }

  async recordSignalOutcome(
    signal_id: string,
    action_id: string,
    req: RecordSignalOutcomeRequest,
  ): Promise<GovernanceSignalAction> {
    const { body } = await this.post<GovernanceSignalAction>(
      `/v1/governance/signals/${encodeURIComponent(signal_id)}/actions/${encodeURIComponent(action_id)}/outcome`,
      req,
    );
    return body;
  }

  async getSignalActionSummary(): Promise<SignalActionSummary> {
    const { body } = await this.get<SignalActionSummary>(
      "/v1/governance/signals/actions/summary",
    );
    return body;
  }

  // ── Cross-Org Impersonation ───────────────────────────────────────────────

  async listImpersonationGrants(): Promise<CrossOrgImpersonationGrant[]> {
    const { body } = await this.get<{ grants: CrossOrgImpersonationGrant[] }>(
      "/v1/cross-org/impersonation/grants",
    );
    return body.grants ?? [];
  }

  async createImpersonationGrant(
    req: CreateImpersonationGrantRequest,
  ): Promise<CrossOrgImpersonationGrant> {
    const { body } = await this.post<CrossOrgImpersonationGrant>(
      "/v1/cross-org/impersonation/grants",
      req,
    );
    return body;
  }

  async revokeImpersonationGrant(id: string): Promise<void> {
    await this.post<Record<string, unknown>>(
      `/v1/cross-org/impersonation/grants/${encodeURIComponent(id)}/revoke`,
      {},
    );
  }

  async issueImpersonationToken(
    grant_id: string,
    requested_duration_seconds?: number,
  ): Promise<ImpersonationToken> {
    const { body } = await this.post<ImpersonationToken>(
      `/v1/cross-org/impersonation/grants/${encodeURIComponent(grant_id)}/token`,
      { requested_duration_seconds },
    );
    return body;
  }

  async validateImpersonationToken(
    token: string,
  ): Promise<ImpersonationValidationResult> {
    const { body } = await this.post<ImpersonationValidationResult>(
      "/v1/cross-org/impersonation/validate",
      { token },
    );
    return body;
  }

  // ── Constrained governance agents (read surface) ──────────────────────────
  //
  // Three GETs onto the v1-governance-agents edge function. Doctrine:
  // findings produced by these endpoints are advisory signal, never
  // authority. There is no `runGovernanceAgent` method on this client —
  // invocation belongs in CI (atlasent-action `governance-agents` mode),
  // not in application code.

  /**
   * List the advisory governance-agent registry for the calling org.
   *
   * Calls `GET /v1/governance/agents`. The registry is reference data
   * seeded at runtime-DB migration time; every row has
   * `authority_class = "advisory"` and `can_authorize = false` —
   * structural invariants enforced by the schema, not policy.
   */
  async listGovernanceAgents(): Promise<GovernanceAgent[]> {
    const { body } = await this.get<ListGovernanceAgentsResponse>(
      "/v1/governance/agents",
    );
    return [...(body.agents ?? [])];
  }

  /**
   * List advisory findings emitted against one governed change.
   *
   * Calls `GET /v1/governance/findings?change_id=…[&agent_slug=…]`.
   * Returns the typed-finding rows in `created_at DESC` order, including
   * `routed_gate_id` when the finding→gate trigger linked them. Findings
   * with `can_authorize === false` (always) are advisory; rendering them
   * never satisfies a gate.
   */
  async listGovernanceFindings(
    query: ListGovernanceFindingsQuery,
  ): Promise<GovernanceAgentFinding[]> {
    if (!query?.change_id) {
      throw new AtlaSentError("change_id is required", { code: "bad_request" });
    }
    const params = new URLSearchParams({ change_id: query.change_id });
    if (query.agent_slug) params.set("agent_slug", query.agent_slug);
    const { body } = await this.get<ListGovernanceFindingsResponse>(
      "/v1/governance/findings",
      params,
    );
    return [...(body.findings ?? [])];
  }

  /**
   * List agent run records against one governed change.
   *
   * Calls `GET /v1/governance/evaluations?change_id=…[&agent_slug=…]`.
   * Returns every persisted evaluation, including `failed` / `timeout`
   * runs and `completed` runs with zero findings — the latter is the
   * positive signal "the agent ran and found nothing", which the UI
   * surfaces as `clear`.
   */
  async listGovernanceEvaluations(
    query: ListGovernanceEvaluationsQuery,
  ): Promise<GovernanceAgentEvaluation[]> {
    if (!query?.change_id) {
      throw new AtlaSentError("change_id is required", { code: "bad_request" });
    }
    const params = new URLSearchParams({ change_id: query.change_id });
    if (query.agent_slug) params.set("agent_slug", query.agent_slug);
    const { body } = await this.get<ListGovernanceEvaluationsResponse>(
      "/v1/governance/evaluations",
      params,
    );
    return [...(body.evaluations ?? [])];
  }

  // ── External Signal Ingestion ─────────────────────────────────────────────

  /**
   * Submit an external assertion to AtlaSent.
   *
   * Records a boolean point-in-time fact from an external connector
   * (GitHub, Stripe, Slack, or any custom source) so that policy rules
   * can reference it during evaluate calls via `context.activeAssertions`
   * or `context.externalAssertions`.
   *
   * Idempotent: submitting an identical assertion that is still within
   * its TTL returns the existing record with `reused: true` rather than
   * creating a duplicate.
   *
   * Calls `POST /v1/assertions`.
   * Requires API key scope `assertions:write`.
   *
   * @example
   * ```ts
   * const result = await client.submitAssertion({
   *   assertion_type: 'github.ci_passed',
   *   source_system:  'github',
   *   subject_ref:    'myorg/myrepo@abc1234',
   *   actor_id:       'github-actions',
   *   action_type:    'production.deploy',
   *   trust_level:    'attested',
   *   valid_until:    new Date(Date.now() + 24 * 3_600_000).toISOString(),
   * });
   * console.log(result.assertion_id, result.reused);
   * ```
   *
   * @throws {@link AtlaSentError} on `401` (invalid key), `403` (missing scope),
   *   `422` (malformed input), `429` (rate limited), or transport failures.
   */
  async submitAssertion(
    input: AssertionSubmitInput,
  ): Promise<AssertionSubmitResult> {
    if (!input.assertion_type || typeof input.assertion_type !== "string") {
      throw new AtlaSentError("assertion_type is required", {
        code: "bad_request",
      });
    }
    if (!input.source_system || typeof input.source_system !== "string") {
      throw new AtlaSentError("source_system is required", {
        code: "bad_request",
      });
    }
    if (!input.subject_ref || typeof input.subject_ref !== "string") {
      throw new AtlaSentError("subject_ref is required", {
        code: "bad_request",
      });
    }

    const wireBody: Record<string, unknown> = {
      assertion_type: input.assertion_type,
      source_system: input.source_system,
      subject_ref: input.subject_ref,
    };
    if (input.actor_id !== undefined) wireBody.actor_id = input.actor_id;
    if (input.action_type !== undefined) wireBody.action_type = input.action_type;
    if (input.payload !== undefined) wireBody.payload = input.payload;
    if (input.trust_level !== undefined) wireBody.trust_level = input.trust_level;
    if (input.valid_until !== undefined) wireBody.valid_until = input.valid_until;

    const { body: wire } = await this.post<{
      assertion_id?: string;
      payload_hash?: string;
      reused?: boolean;
    }>("/v1/assertions", wireBody);

    if (
      typeof wire.assertion_id !== "string" ||
      wire.assertion_id.length === 0
    ) {
      throw new AtlaSentError(
        "Malformed response from /v1/assertions: missing `assertion_id`",
        { code: "bad_response" },
      );
    }
    if (
      typeof wire.payload_hash !== "string" ||
      wire.payload_hash.length === 0
    ) {
      throw new AtlaSentError(
        "Malformed response from /v1/assertions: missing `payload_hash`",
        { code: "bad_response" },
      );
    }

    return {
      assertion_id: wire.assertion_id,
      payload_hash: wire.payload_hash,
      reused: wire.reused ?? false,
    };
  }

  // ── RBAC Rules ────────────────────────────────────────────────────────────

  async listRbacRules(
    orgId: string,
    options: { limit?: number; offset?: number } = {},
  ): Promise<ListRbacRulesResponse> {
    const params = new URLSearchParams({ org_id: orgId });
    if (options.limit !== undefined) params.set("limit", String(options.limit));
    if (options.offset !== undefined) params.set("offset", String(options.offset));
    const { body } = await this.get<ListRbacRulesResponse>("/v1/rbac-rules", params);
    return { rules: body.rules ?? [], total: body.total };
  }

  async createRbacRule(input: CreateRbacRuleRequest): Promise<RbacRule> {
    const { body } = await this.post<{ rule: RbacRule }>("/v1/rbac-rules", input);
    return body.rule;
  }

  async deleteRbacRule(id: string): Promise<void> {
    await this._delete(`/v1/rbac-rules/${encodeURIComponent(id)}`);
  }

  // ── Approvals SLA ─────────────────────────────────────────────────────────

  async getApprovalSla(
    orgId: string,
    options: { days?: number } = {},
  ): Promise<GetApprovalSlaResponse> {
    const params = new URLSearchParams({ org_id: orgId });
    if (options.days !== undefined) params.set("days", String(options.days));
    const { body } = await this.get<GetApprovalSlaResponse>(
      "/v1/approvals/sla",
      params,
    );
    return body;
  }

  // ── Private adapters for sub-client factories ──────────────────────────────
  // Thin wrappers that expose the private request infrastructure to sub-client
  // factories (scim, evidenceBundles, auth) without widening the public API.

  private async _post<T>(
    path: string,
    body: unknown,
    query?: URLSearchParams,
  ): Promise<{ body: T }> {
    const { body: b } = await this.post<T>(path, body, query);
    return { body: b };
  }

  private async _get<T>(
    path: string,
    query?: URLSearchParams,
  ): Promise<{ body: T }> {
    const { body: b } = await this.get<T>(path, query);
    return { body: b };
  }

  private async _put<T>(path: string, body: unknown): Promise<{ body: T }> {
    return this._requestRaw<T>(path, "PUT", body, undefined);
  }

  private async _patch<T>(path: string, body: unknown): Promise<{ body: T }> {
    return this._requestRaw<T>(path, "PATCH", body, undefined);
  }

  private async _delete(path: string): Promise<void> {
    await this._requestRaw<Record<string, unknown>>(path, "DELETE", undefined, undefined);
  }

  private async _getRaw(path: string): Promise<ArrayBuffer> {
    const url = `${this.baseUrl}${path}`;
    const requestId = globalThis.crypto.randomUUID();
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiKey}`,
      "User-Agent": this.userAgent,
      ...this.regionHeaders,
      "X-Request-ID": requestId,
      "X-AtlaSent-Protocol-Version": "1",
    };
    const response = await this.fetchImpl(url, {
      method: "GET",
      headers,
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new AtlaSentError(`GET ${path} returned ${response.status}`, {
        code: response.status >= 500 ? "server_error" : "bad_request",
        status: response.status,
        requestId,
      });
    }
    return response.arrayBuffer();
  }

  private async _requestRaw<T>(
    path: string,
    method: "PUT" | "PATCH" | "DELETE",
    body: unknown,
    query: URLSearchParams | undefined,
  ): Promise<{ body: T }> {
    const qs =
      query && Array.from(query).length > 0 ? `?${query.toString()}` : "";
    const url = `${this.baseUrl}${path}${qs}`;
    const requestId = globalThis.crypto.randomUUID();
    const headers: Record<string, string> = {
      Accept: "application/json",
      Authorization: `Bearer ${this.apiKey}`,
      "User-Agent": this.userAgent,
      ...this.regionHeaders,
      "X-Request-ID": requestId,
      "X-AtlaSent-Protocol-Version": "1",
    };
    if (method === "PUT" && body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    const init: RequestInit = { method, headers, signal: AbortSignal.timeout(this.timeoutMs) };
    if (method === "PUT" && body !== undefined) {
      init.body = JSON.stringify(body);
    }
    const response = await this.fetchImpl(url, init);
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new AtlaSentError(`${method} ${path} returned ${response.status}`, {
        code: response.status >= 500 ? "server_error" : "bad_request",
        status: response.status,
        requestId,
      });
    }
    if (method === "DELETE") {
      return { body: {} as T };
    }
    return { body: (await response.json()) as T };
  }
}

/**
 * Parse the server's `X-RateLimit-*` header triple into a typed
 * {@link RateLimitState}. Returns `null` when any of the three headers
 * is missing or unparseable — callers treat that as "the server didn't
 * emit rate-limit state" rather than "the window is empty".
 *
 * `X-RateLimit-Reset` is accepted as either unix-seconds (what the
 * AtlaSent edge functions emit today) or an ISO 8601 timestamp.
 */
function parseRateLimitHeaders(headers: Headers): RateLimitState | null {
  const rawLimit = headers.get("x-ratelimit-limit");
  const rawRemaining = headers.get("x-ratelimit-remaining");
  const rawReset = headers.get("x-ratelimit-reset");
  if (rawLimit === null || rawRemaining === null || rawReset === null) {
    return null;
  }
  const limit = Number(rawLimit);
  const remaining = Number(rawRemaining);
  if (!Number.isFinite(limit) || !Number.isFinite(remaining)) {
    return null;
  }
  const resetAt = parseResetHeader(rawReset);
  if (resetAt === null) {
    return null;
  }
  return { limit, remaining, resetAt };
}

function parseResetHeader(raw: string): Date | null {
  const seconds = Number(raw);
  if (Number.isFinite(seconds)) {
    // Standard shape: unix seconds. 10-digit values are in the valid
    // range ~2001–2286 so this heuristic won't confuse a tiny
    // `remaining`-like number for an epoch.
    return new Date(seconds * 1000);
  }
  const ms = Date.parse(raw);
  if (Number.isFinite(ms)) {
    return new Date(ms);
  }
  return null;
}

function mapFetchError(err: unknown, requestId: string): AtlaSentError {
  if (err instanceof AtlaSentError) return err;
  if (err instanceof DOMException && err.name === "TimeoutError") {
    return new AtlaSentError("Request to AtlaSent API timed out", {
      code: "timeout",
      requestId,
      cause: err,
    });
  }
  if (err instanceof Error && err.name === "AbortError") {
    return new AtlaSentError("Request to AtlaSent API timed out", {
      code: "timeout",
      requestId,
      cause: err,
    });
  }
  const message = err instanceof Error ? err.message : "network error";
  return new AtlaSentError(`Failed to reach AtlaSent API: ${message}`, {
    code: "network",
    requestId,
    cause: err,
  });
}

async function buildHttpError(
  response: Response,
  requestId: string,
): Promise<AtlaSentError> {
  const status = response.status;
  const classified = await classifyHttpStatus(response);
  const init: AtlaSentErrorInit = {
    status,
    code: classified.code,
    requestId,
  };
  if (classified.retryAfterMs !== undefined) {
    init.retryAfterMs = classified.retryAfterMs;
  }
  // #1634: the wire envelope for a permit-mint/signing failure is a
  // non-2xx status (503 recoverable / 500 invariant) carrying
  // `{"error": "permit_signing_unavailable", ...}`. Surface it as a
  // distinct, structurally recognizable error class rather than the
  // generic AtlaSentError every other non-2xx response gets, so
  // application code can tell "AtlaSent could not materialize executable
  // authority" apart from an ordinary transport/auth/rate-limit failure.
  if (classified.code === "permit_signing_unavailable") {
    return new AtlaSentPermitMintFailedError(classified.message, init);
  }
  return new AtlaSentError(classified.message, init);
}

async function classifyHttpStatus(response: Response): Promise<{
  message: string;
  code: AtlaSentErrorCode;
  retryAfterMs: number | undefined;
}> {
  const status = response.status;
  const { message: serverMessage, errorCode } = await readServerBody(response);

  if (status === 401) {
    return {
      message: serverMessage ?? "Invalid API key",
      code: "invalid_api_key",
      retryAfterMs: undefined,
    };
  }
  if (status === 403) {
    return {
      message:
        serverMessage ?? "Access forbidden — check your API key permissions",
      code: "forbidden",
      retryAfterMs: undefined,
    };
  }
  if (status === 429) {
    return {
      message: serverMessage ?? "Rate limited by AtlaSent API",
      code: "rate_limited",
      retryAfterMs: parseRetryAfter(response.headers.get("retry-after")),
    };
  }
  if (status >= 500) {
    // #1634: the wire envelope for a permit-mint/signing failure is a
    // non-2xx status carrying `{"error": "permit_signing_unavailable", ...}`.
    if (errorCode !== null && PERMIT_MINT_FAILURE_ERROR_CODES.has(errorCode)) {
      return {
        message: serverMessage ?? `AtlaSent API returned HTTP ${status}`,
        code: errorCode as AtlaSentErrorCode,
        retryAfterMs: undefined,
      };
    }
    return {
      message: serverMessage ?? `AtlaSent API returned HTTP ${status}`,
      code: "server_error",
      retryAfterMs: undefined,
    };
  }
  return {
    message: serverMessage ?? `AtlaSent API returned HTTP ${status}`,
    code: "bad_request",
    retryAfterMs: undefined,
  };
}

/**
 * Read the response body once and extract both the human-readable
 * message and, when present, the machine-readable `error` code —
 * `Response.text()` can only be consumed once, so both must come from
 * the same read.
 */
async function readServerBody(
  response: Response,
): Promise<{ message: string | null; errorCode: string | null }> {
  try {
    const text = await response.text();
    if (!text) return { message: null, errorCode: null };
    let errorCode: string | null = null;
    try {
      const parsed = JSON.parse(text);
      if (parsed && typeof parsed === "object") {
        const error = (parsed as Record<string, unknown>).error;
        errorCode = typeof error === "string" ? error : null;
        const msg = (parsed as Record<string, unknown>).message;
        const reason = (parsed as Record<string, unknown>).reason;
        if (typeof msg === "string" && msg.length > 0) {
          return { message: msg, errorCode };
        }
        if (typeof reason === "string" && reason.length > 0) {
          return { message: reason, errorCode };
        }
        // Neither `message` nor `reason` present — fall through to the
        // raw-text fallback below, same as before `error` was inspected.
      }
    } catch {
      // Fall through — treat as plain text.
    }
    return {
      message: text.length > 500 ? `${text.slice(0, 500)}…` : text,
      errorCode,
    };
  } catch {
    return { message: null, errorCode: null };
  }
}

/**
 * Translate an {@link AuditEventsQuery} into `URLSearchParams`. The
 * server expects snake_case keys (`actor_id`) and accepts
 * comma-joined values for `types`; numeric `limit` serializes via
 * `String(n)`. Undefined / empty fields are dropped so the query
 * string stays minimal.
 */
function buildAuditEventsQuery(query: AuditEventsQuery): URLSearchParams {
  const params = new URLSearchParams();
  if (query.types !== undefined && query.types !== "") {
    params.set("types", query.types);
  }
  if (query.actor_id !== undefined && query.actor_id !== "") {
    params.set("actor_id", query.actor_id);
  }
  if (query.from !== undefined && query.from !== "") {
    params.set("from", query.from);
  }
  if (query.to !== undefined && query.to !== "") {
    params.set("to", query.to);
  }
  if (query.limit !== undefined) {
    params.set("limit", String(query.limit));
  }
  if (query.cursor !== undefined && query.cursor !== "") {
    params.set("cursor", query.cursor);
  }
  return params;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseRetryAfter(raw: string | null): number | undefined {
  if (!raw) return undefined;
  const seconds = Number(raw);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
  const date = Date.parse(raw);
  if (Number.isFinite(date)) {
    const delta = date - Date.now();
    return delta > 0 ? delta : 0;
  }
  return undefined;
}

// ── SSE stream parser ─────────────────────────────────────────────────────────

/**
 * Parse an SSE `ReadableStream<Uint8Array>` into typed {@link StreamEvent}s.
 *
 * Hardening additions over the original:
 * - Per-event timeout: if no chunk arrives within `timeoutMs` (0 = disabled),
 *   throws {@link StreamTimeoutError}.
 * - Partial-JSON guard: wraps `JSON.parse` failures in {@link StreamParseError}
 *   rather than letting the raw `SyntaxError` escape.
 * - Calls `onEventId` whenever the server emits an `id:` field so the caller
 *   can track the `Last-Event-ID` for reconnection.
 * - Terminal detection: returns on the real V2-D4 `event: complete` frame
 *   (`{batch_id, count, partial}`), the legacy/generic `event: done`, OR when
 *   a `decision` event carries `done: true` at the top level.
 *
 * Decision frames tolerate both the real wire shape (`{index, decision,
 * permit_token, reason, audit_hash, timestamp}` — the same canonical shape
 * `evaluate()` parses, with no `is_final` field at all) and the legacy
 * `{permitted, decision_id, is_final}` shape some older mocks/servers still
 * emit. `permit_token` is preferred over `decision_id` when both are
 * present. Because the caller (`protectStream()`) always submits a
 * single-item `items` array, a canonical decision frame with no `is_final`
 * field defaults to final — it IS the one and only decision for that call.
 * An explicit legacy `is_final: false` is still honoured when present.
 * Error frames prefer the real `error_code` field over the legacy `code`.
 */
async function* parseSseStream(
  body: ReadableStream<Uint8Array>,
  requestId: string,
  timeoutMs: number,
  onEventId: (id: string) => void,
): AsyncIterable<StreamEvent> {
  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buf = "";

  type ChunkResult =
    | { done: true; value?: undefined }
    | { done: false; value: Uint8Array };

  /**
   * Read the next chunk from the reader, applying a per-read timeout when
   * `timeoutMs > 0`. Returns `{ done: true }` when the stream ends, throws
   * {@link StreamTimeoutError} on timeout.
   */
  async function readChunk(): Promise<ChunkResult> {
    if (timeoutMs <= 0) {
      return reader.read() as Promise<ChunkResult>;
    }
    return new Promise<ChunkResult>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new StreamTimeoutError(timeoutMs));
      }, timeoutMs);
      (reader.read() as Promise<ChunkResult>).then(
        (result) => {
          clearTimeout(timer);
          resolve(result);
        },
        (err: unknown) => {
          clearTimeout(timer);
          reject(err);
        },
      );
    });
  }

  try {
    for (;;) {
      let done: boolean;
      let value: Uint8Array | undefined;
      try {
        const result = await readChunk();
        done = result.done;
        value = result.value;
      } catch (err) {
        if (err instanceof StreamTimeoutError) throw err;
        // Network error mid-stream: surface as AtlaSentError(network) so the
        // caller's reconnection loop can catch and retry.
        throw new AtlaSentError(
          `AtlaSent stream read failed: ${err instanceof Error ? err.message : String(err)}`,
          { code: "network", requestId, cause: err },
        );
      }

      if (done) break;
      buf += decoder.decode(value, { stream: true });

      let boundary: number;
      while ((boundary = buf.indexOf("\n\n")) !== -1) {
        const block = buf.slice(0, boundary);
        buf = buf.slice(boundary + 2);

        let eventType = "message";
        let data = "";
        let eventId: string | undefined;
        for (const line of block.split("\n")) {
          if (line.startsWith("event: ")) eventType = line.slice(7).trim();
          else if (line.startsWith("data: ")) data = line.slice(6);
          else if (line.startsWith("id: ")) eventId = line.slice(4).trim();
          else if (line.startsWith("id:")) eventId = line.slice(3).trim();
        }

        if (eventId !== undefined) onEventId(eventId);

        if (!data) continue;
        // "complete" is the real V2-D4 terminal frame emitted by
        // /v1-evaluate-stream once every item in the request's `items`
        // array has been evaluated; "done" is the legacy/generic terminal
        // marker kept for backward compatibility with older mocks/servers.
        if (eventType === "complete" || eventType === "done") return;

        let parsed: unknown;
        try {
          parsed = JSON.parse(data);
        } catch (err) {
          throw new StreamParseError(data, err);
        }

        if (eventType === "error") {
          const e = parsed as {
            error_code?: string;
            code?: string;
            message?: string;
            request_id?: string;
          };
          // Real wire frame (`{index, error_code, message}`) uses
          // `error_code`; `code` is kept as a fallback for the legacy/
          // generic shape some older mocks and tests still use.
          throw new AtlaSentError(
            e.message ?? "Stream error from AtlaSent API",
            {
              code: (e.error_code ?? e.code ?? "server_error") as AtlaSentErrorCode,
              requestId: e.request_id ?? requestId,
            },
          );
        }

        if (eventType === "decision") {
          const d = parsed as {
            // Real wire shape: the same canonical {decision, permit_token}
            // fields evaluate() parses, prefixed with `index` on the batch.
            decision?: string;
            permit_token?: string;
            // Legacy/generic shape, tolerated for backward compatibility.
            permitted?: boolean;
            decision_id?: string;
            is_final?: boolean;
            reason?: string;
            audit_hash?: string;
            timestamp?: string;
            done?: boolean;
          };

          // Normalise decision to lowercase canonical form, tolerating both
          // the canonical {decision} string and the legacy {permitted}
          // boolean — mirrors evaluate()'s own compat handling.
          let streamDecision: DecisionCanonical | undefined =
            typeof d.decision === "string"
              ? (d.decision.toLowerCase() as DecisionCanonical)
              : undefined;
          if (streamDecision === undefined && typeof d.permitted === "boolean") {
            streamDecision = d.permitted ? "allow" : "deny";
          }
          if (
            streamDecision !== "allow" &&
            streamDecision !== "deny" &&
            streamDecision !== "hold" &&
            streamDecision !== "escalate"
          ) {
            throw new AtlaSentError(
              "Malformed decision event from AtlaSent API: missing `decision` (or legacy `permitted`)",
              {
                code: "bad_response",
                requestId,
              },
            );
          }

          // Prefer the canonical `permit_token`; fall back to the legacy
          // `decision_id` when both are present.
          const permitId = d.permit_token ?? d.decision_id ?? "";
          // The real V2-D4 wire's `event: decision` frames never carry
          // `is_final` at all (see the decisionWire fixture in
          // test/stream.test.ts) — the legacy/generic shape is the only one
          // that ever sets it explicitly. protectStream() always submits a
          // single-item `items` array (see the request body above), so a
          // canonical decision frame with no `is_final` field IS the final
          // (and only) decision for this call: default to final rather than
          // non-final so the documented `if (event.isFinal) verifyPermit(...)`
          // pattern actually fires. Explicit legacy `is_final: false` (an
          // interim decision) is still honoured when present.
          const isFinal = typeof d.is_final === "boolean" ? d.is_final : true;
          yield {
            type: "decision",
            decision: streamDecision,
            decision_canonical: streamDecision,
            permitId,
            reason: d.reason ?? "",
            auditHash: d.audit_hash ?? "",
            timestamp: d.timestamp ?? "",
            isFinal,
          } satisfies StreamDecisionEvent;

          // Terminal: final decision OR inline done: true closes the stream.
          if (isFinal || d.done === true) return;
        } else if (eventType === "progress") {
          const p = parsed as Record<string, unknown>;
          yield {
            type: "progress",
            stage: String(p["stage"] ?? ""),
            ...p,
          } satisfies StreamProgressEvent;
          // Server may signal terminal state via done: true on any event type.
          if ((p as Record<string, unknown>).done === true) return;
        } else {
          // Unknown event type: check for done: true as a terminal signal.
          if (
            parsed !== null &&
            typeof parsed === "object" &&
            (parsed as Record<string, unknown>).done === true
          ) {
            return;
          }
        }
        // Unknown event types skipped for forward compatibility.
      }
    }

    // Stream closed before an explicit `event: done`. If there's leftover
    // partial data in the buffer, it means the stream was cut mid-event.
    if (buf.trim().length > 0) {
      throw new StreamParseError(buf);
    }
  } finally {
    reader.releaseLock();
  }
}
