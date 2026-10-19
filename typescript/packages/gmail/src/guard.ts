/**
 * AtlaSent send-time authorization gate for the Gmail API.
 *
 * Implements the founder-decided interception mechanism (2026-08-09) for
 * CANON-000047 / ACT-0050 (communication.external.send — atlasent core
 * repo `contract/canonical-actions/ACT-0050-communication-external-send.yaml`):
 * a SEND-TIME API GATE. AtlaSent evaluates and verifies the send BEFORE
 * the caller's own Gmail API call is ever made — a denied or unverified
 * request never reaches Gmail. See
 * `atlasent/contract/safeguard-pack/connector-readiness/gmail.readiness.yaml`
 * for this connector's current evidence-level state (this package is real
 * G3 code, but has never been exercised against a live Gmail/Workspace
 * account or a real Google Cloud OAuth client — see this repo's README
 * for what remains an open operator prerequisite).
 *
 *   1. evaluate     — check the policy engine (communication.external.send)
 *   2. verifyPermit — confirm and consume the permit
 *   3. send         — call the real Gmail API ONLY if both pass
 *
 * Fail-closed throughout: an evaluate/verify error, a deny/hold/escalate
 * decision, a permit that does not verify, or one that verified without being
 * consumed all block the real Gmail API call. `runGuardedSend` is the ONLY
 * place in this package that calls Gmail's send endpoints, strictly after
 * both checks pass.
 *
 * WHAT THE PERMIT IS BOUND TO (0.2.0). The guard snapshots the exact request
 * Gmail will receive — the base64url `raw` RFC 2822 message (which carries the
 * recipients, subject, body and attachments), the `userId` and the `threadId`
 * — and hashes it. That digest goes to evaluate twice:
 *
 *   - as top-level `execution_payload_hash`, which the runtime signs into the
 *     permit, and which the guard re-presents at verify; and
 *   - as top-level `resource_id`, which the runtime folds into the
 *     `action_hash` a human `approval_artifact.v1` signs. An approval for one
 *     message therefore cannot authorize another.
 *
 * Gmail is then called with a request built from that snapshot, never with
 * the caller's own object, so mutating it after the call starts changes
 * nothing that is sent.
 *
 * Before 0.2.0 the guard bound only caller-supplied facts, and presented at
 * verify a digest of `{action_type, actor_id, context}` that matched nothing
 * the runtime binds (it omitted the posted `environment` and the runtime's
 * `sha256:` prefix): every send ended in `PAYLOAD_MISMATCH`, and a caller's
 * `approvals` count was sent as if it were evidence. See the README.
 *
 * The {@link GmailExternalSendFacts} remain caller-asserted classification
 * inputs (recipient domain, known-recipient, sensitivity). This package does
 * not parse MIME, so it does not check them against the bytes; a human
 * approval covers the bytes and the facts together.
 */

import type { gmail_v1 } from "googleapis";
import type { AtlaSentClient, EvaluateResponse, EvaluateSigningHint, VerifyPermitResponse } from "@atlasent/sdk";

/** ACT-0050 / CANON-000047 canonical action_type — see the atlasent core repo's
 * `contract/canonical-actions/ACT-0050-communication-external-send.yaml`. */
export const COMMUNICATION_EXTERNAL_SEND = "communication.external.send" as const;

/** Version tag folded into the message digest; changing the digest input bumps it. */
export const GMAIL_SEND_BINDING_VERSION = "gmail_send_binding.v1" as const;

/**
 * Classification facts for one outbound external send — policy inputs the
 * caller asserts. The permit and any human approval are bound to the exact
 * message bytes as well (see the module doc), not to these alone.
 */
export interface GmailExternalSendFacts {
  /** Exact recipient address (or a stable joined form for multiple recipients — e.g. sorted, comma-joined). */
  recipient: string;
  /** Whether the recipient is a previously-known/verified correspondent. */
  recipientKnown: boolean;
  /** Whether this send carries a flagged-sensitive attachment or body. */
  sensitiveAttachment: boolean;
  /**
   * SHA-256 hex content hash of the attachment/body when
   * `sensitiveAttachment` is true. Omit (or pass `""`) when there is no
   * sensitive content to hash.
   */
  attachmentSha256?: string;
  /**
   * Recipient domain — the `recipient_domain` required_context_inputs
   * presence gate on the runtime's `communication.external.send` action
   * class. Derived from `recipient` (text after the last `@`) when
   * omitted and `recipient` contains an `@`.
   */
  recipientDomain?: string;
  /**
   * @deprecated Ignored since 0.2.0. `context.approvals` is now derived from
   * whether a signed approval is attached ({@link GmailSendGuardOptions.approvalArtifact}).
   * A caller-supplied count is a claim the runtime cannot check, and on an
   * action class that does not demand an artifact it would have been accepted
   * as the approval itself.
   */
  approvals?: number;
  /**
   * Whether this send was initiated by a human or an AI agent. Policy
   * context / audit evidence only — no rule template or handler branch
   * in the runtime reads this value to select a different code path
   * (human/AI equivalence is a deliberate property of ACT-0050).
   */
  actorOrigin?: "human" | "ai_agent";
}

export interface GmailSendGuardOptions {
  /** AtlaSent actor identifier for the caller (e.g. `"user:sales-rep-01"`, `"agent:outreach-assistant"`). */
  agent: string;
  /** Deployment environment forwarded to evaluate/verify. Defaults to `"production"`. */
  environment?: string;
  /**
   * Extra context merged into the evaluate call. The guard's own fields
   * (`approvals`, `recipient_known`, `recipient_domain`, `sensitive_attachment`,
   * `actor_origin`, `target`) always win. Pass the same value to the approval
   * request and to the send, or the approval will not match.
   */
  extraContext?: Record<string, unknown>;
  /**
   * A signed `approval_artifact.v1` for THIS message, sent as
   * `approval.artifact`. Obtain the `action_hash` it must sign from
   * {@link requestGmailSendApproval} / {@link requestGmailSendDraftApproval}.
   * Without it the guard reports zero approvals.
   */
  approvalArtifact?: Record<string, unknown>;
  /**
   * - `"result"` (default) — return a {@link GmailSendDenial} discriminated-union member on any block.
   * - `"throw"` — throw a {@link GmailSendDeniedError} on any block instead.
   */
  onDeny?: "result" | "throw";
}

export interface GmailSendDenial {
  sent: false;
  /** `"deny"` | `"hold"` | `"escalate"` | `"verify_failed"` | `"invalid_request"` | `"content_changed"` | `"error"`. */
  decision: string;
  reason: string;
  /** Stable machine deny code (e.g. `"INSUFFICIENT_APPROVALS"`, `"NO_TEMPLATE_MATCH"`) when the block came from an evaluate-time deny. `undefined` on verify failures and transport errors. */
  denyCode?: string;
  evaluationId?: string;
  auditHash?: string;
  /** Digest of the message the guard would have sent, when it got that far. */
  messageDigest?: string;
}

export interface GmailSendSuccess<TResponse> {
  sent: true;
  /** The real Gmail API response — only ever populated once the send actually happened. */
  message: TResponse;
  permitId: string;
  auditHash: string;
  /** Digest of the exact request sent; the value the permit was bound to. */
  messageDigest: string;
}

export type GmailSendResult<TResponse> = GmailSendSuccess<TResponse> | GmailSendDenial;

/** What a human approval for one message must bind. */
export type GmailSendApprovalRequest =
  | {
      ok: true;
      /** Sign `signingHint.bind.action_hash` into an `approval_artifact.v1`. */
      signingHint: EvaluateSigningHint;
      /** Digest of the message the approval covers, for display and audit. */
      messageDigest: string;
    }
  | {
      ok: false;
      reason: string;
      decision?: string;
      denyCode?: string;
      messageDigest?: string;
    };

/** Thrown by the guard when `onDeny: "throw"` and the send is blocked. */
export class GmailSendDeniedError extends Error {
  override name = "GmailSendDeniedError";
  readonly denial: GmailSendDenial;
  constructor(denial: GmailSendDenial) {
    super(`Gmail send blocked: ${denial.decision} — ${denial.reason}`);
    this.denial = denial;
  }
}

function targetIdInput(facts: GmailExternalSendFacts): Record<string, unknown> {
  return {
    recipient: facts.recipient,
    attachment_sha256: facts.attachmentSha256 ?? "",
    sensitive_attachment: facts.sensitiveAttachment,
  };
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * SHA-256 hex digest over the recipient/attachment/sensitivity facts, sent
 * as `context.target.id`. Exported for callers that log or correlate it.
 */
export async function computeExternalSendTargetId(facts: GmailExternalSendFacts): Promise<string> {
  return sha256Hex(JSON.stringify(targetIdInput(facts)));
}

/** Sort object keys recursively so the JSON serialization is deterministic. */
function sortKeysDeep(val: unknown): unknown {
  if (Array.isArray(val)) return val.map(sortKeysDeep);
  if (val !== null && typeof val === "object") {
    return Object.keys(val as object)
      .sort()
      .reduce<Record<string, unknown>>((acc, k) => {
        acc[k] = sortKeysDeep((val as Record<string, unknown>)[k]);
        return acc;
      }, {});
  }
  return val;
}

/** The exact request Gmail will receive, frozen before evaluate. */
export interface GmailSendSnapshot {
  kind: "message" | "draft";
  userId: string;
  /** base64url RFC 2822 message: recipients, headers, body and attachments. */
  raw: string;
  threadId: string | null;
  /** The draft sent, for `kind: "draft"`. */
  draftId: string | null;
}

/**
 * Bare 64-hex SHA-256 over the canonical snapshot — the value sent as
 * `execution_payload_hash` and `resource_id`. Exported so an approval UI can
 * show which message an approval covers.
 */
export async function computeGmailSendDigest(snapshot: GmailSendSnapshot): Promise<string> {
  return sha256Hex(JSON.stringify(sortKeysDeep({ binding_version: GMAIL_SEND_BINDING_VERSION, ...snapshot })));
}

class InvalidSendRequest extends Error {}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function snapshotMessageRequest(request: gmail_v1.Params$Resource$Users$Messages$Send): GmailSendSnapshot {
  if (!nonEmpty(request.userId)) throw new InvalidSendRequest("userId is required");
  if (request.media !== undefined) {
    // A media upload is sent instead of requestBody.raw; the guard cannot bind it.
    throw new InvalidSendRequest("media uploads are not supported: pass the message as requestBody.raw");
  }
  const raw = request.requestBody?.raw;
  if (!nonEmpty(raw)) throw new InvalidSendRequest("requestBody.raw is required");
  const threadId = request.requestBody?.threadId;
  return Object.freeze({
    kind: "message",
    userId: request.userId,
    raw,
    threadId: nonEmpty(threadId) ? threadId : null,
    draftId: null,
  });
}

/** Reads the draft's current content; drafts.send sends what Gmail holds, not what the caller passes. */
async function snapshotDraft(
  gmail: Pick<gmail_v1.Gmail, "users">,
  userId: string,
  draftId: string,
): Promise<GmailSendSnapshot> {
  const draft = (await gmail.users.drafts.get({ userId, id: draftId, format: "raw" })).data;
  const raw = draft.message?.raw;
  if (!nonEmpty(raw)) throw new InvalidSendRequest(`draft ${draftId} has no raw content`);
  const threadId = draft.message?.threadId;
  return Object.freeze({ kind: "draft", userId, raw, threadId: nonEmpty(threadId) ? threadId : null, draftId });
}

function draftIdOf(request: gmail_v1.Params$Resource$Users$Drafts$Send): { userId: string; draftId: string } {
  if (!nonEmpty(request.userId)) throw new InvalidSendRequest("userId is required");
  if (request.media !== undefined || request.requestBody?.message !== undefined) {
    // Either would replace the draft's content at send time with bytes the guard never bound.
    throw new InvalidSendRequest("drafts.send with replacement content is not supported: update the draft, then send it by id");
  }
  const draftId = request.requestBody?.id;
  if (!nonEmpty(draftId)) throw new InvalidSendRequest("requestBody.id (the draft id) is required");
  return { userId: request.userId, draftId };
}

function deriveRecipientDomain(facts: GmailExternalSendFacts): string | undefined {
  if (facts.recipientDomain) return facts.recipientDomain;
  const at = facts.recipient.lastIndexOf("@");
  return at === -1 ? undefined : facts.recipient.slice(at + 1);
}

function blocked(options: GmailSendGuardOptions, d: GmailSendDenial): GmailSendDenial {
  if ((options.onDeny ?? "result") === "throw") {
    throw new GmailSendDeniedError(d);
  }
  return d;
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

async function buildContext(
  facts: GmailExternalSendFacts,
  options: GmailSendGuardOptions,
  approvalsClaimed: 0 | 1,
): Promise<Record<string, unknown>> {
  const context: Record<string, unknown> = {
    ...options.extraContext,
    recipient_known: facts.recipientKnown,
    sensitive_attachment: facts.sensitiveAttachment,
    approvals: approvalsClaimed,
    target: { id: await computeExternalSendTargetId(facts) },
  };
  const recipientDomain = deriveRecipientDomain(facts);
  if (recipientDomain !== undefined) context["recipient_domain"] = recipientDomain;
  if (facts.actorOrigin !== undefined) context["actor_origin"] = facts.actorOrigin;
  return context;
}

/**
 * The single place the evaluate request is composed, shared by the approval
 * request and the send so both present the same `action_hash` inputs. They
 * differ only in `approval`.
 */
async function evaluateSend(
  atlasent: AtlaSentClient,
  facts: GmailExternalSendFacts,
  options: GmailSendGuardOptions,
  digest: string,
  approvalsClaimed: 0 | 1,
  approvalArtifact: Record<string, unknown> | undefined,
): Promise<EvaluateResponse> {
  return atlasent.evaluate({
    actor_id: options.agent,
    action_type: COMMUNICATION_EXTERNAL_SEND,
    environment: options.environment ?? "production",
    context: await buildContext(facts, options, approvalsClaimed),
    resource_id: digest,
    execution_payload_hash: digest,
    ...(approvalArtifact !== undefined ? { approval: { artifact: approvalArtifact } } : {}),
  });
}

/**
 * Authorize-then-send: evaluate + verify `communication.external.send`
 * BEFORE calling `gmail.users.messages.send`. Fail-closed — the real
 * Gmail API call happens ONLY when the permit was verified and consumed,
 * and it sends exactly the `userId` / `raw` / `threadId` the permit is
 * bound to. Other `requestBody` fields are not sent.
 *
 * @example
 * ```ts
 * const approval = await requestGmailSendApproval(atlasent, request, facts, { agent });
 * // A human reviews the message and signs approval.signingHint.bind.action_hash.
 * const result = await guardedGmailSend(gmail, atlasent, request, facts, {
 *   agent,
 *   approvalArtifact: signedArtifact,
 * });
 * ```
 */
export async function guardedGmailSend(
  gmail: Pick<gmail_v1.Gmail, "users">,
  atlasent: AtlaSentClient,
  request: gmail_v1.Params$Resource$Users$Messages$Send,
  facts: GmailExternalSendFacts,
  options: GmailSendGuardOptions,
): Promise<GmailSendResult<gmail_v1.Schema$Message>> {
  let snapshot: GmailSendSnapshot;
  try {
    snapshot = snapshotMessageRequest(request);
  } catch (err) {
    return blocked(options, { sent: false, decision: "invalid_request", reason: errorText(err) });
  }
  const outbound: gmail_v1.Params$Resource$Users$Messages$Send = {
    userId: snapshot.userId,
    requestBody: { raw: snapshot.raw, ...(snapshot.threadId !== null ? { threadId: snapshot.threadId } : {}) },
  };
  return runGuardedSend(atlasent, facts, options, snapshot, null, async () =>
    (await gmail.users.messages.send(outbound)).data,
  );
}

/**
 * Authorize-then-send an existing draft via `gmail.users.drafts.send`.
 *
 * Gmail sends the draft's content as Gmail holds it, so the guard reads it
 * (`drafts.get`, `format: "raw"`), binds those bytes, and reads it again
 * immediately before sending: an edit after authorization refuses the send
 * (`content_changed`). A change in the instant between that read and Gmail's
 * own send is not observable from a client. The `gmail.compose` scope covers
 * both calls. `gmail.users.drafts.create` is not wrapped: it delivers no mail.
 */
export async function guardedGmailSendDraft(
  gmail: Pick<gmail_v1.Gmail, "users">,
  atlasent: AtlaSentClient,
  request: gmail_v1.Params$Resource$Users$Drafts$Send,
  facts: GmailExternalSendFacts,
  options: GmailSendGuardOptions,
): Promise<GmailSendResult<gmail_v1.Schema$Message>> {
  let snapshot: GmailSendSnapshot;
  try {
    const { userId, draftId } = draftIdOf(request);
    snapshot = await snapshotDraft(gmail, userId, draftId);
  } catch (err) {
    return blocked(options, {
      sent: false,
      decision: err instanceof InvalidSendRequest ? "invalid_request" : "error",
      reason: err instanceof InvalidSendRequest ? errorText(err) : `could not read the draft: ${errorText(err)}`,
    });
  }
  const draftId = snapshot.draftId as string;
  return runGuardedSend(
    atlasent,
    facts,
    options,
    snapshot,
    async () => computeGmailSendDigest(await snapshotDraft(gmail, snapshot.userId, draftId)),
    async () => (await gmail.users.drafts.send({ userId: snapshot.userId, requestBody: { id: draftId } })).data,
  );
}

async function runGuardedSend<TResponse>(
  atlasent: AtlaSentClient,
  facts: GmailExternalSendFacts,
  options: GmailSendGuardOptions,
  snapshot: GmailSendSnapshot,
  rereadDigest: (() => Promise<string>) | null,
  performSend: () => Promise<TResponse>,
): Promise<GmailSendResult<TResponse>> {
  const environment = options.environment ?? "production";
  const messageDigest = await computeGmailSendDigest(snapshot);
  const artifact = options.approvalArtifact;

  let evalResp: EvaluateResponse;
  try {
    // Report an approval only when one is attached for the runtime to verify.
    evalResp = await evaluateSend(atlasent, facts, options, messageDigest, artifact !== undefined ? 1 : 0, artifact);
  } catch (err) {
    return blocked(options, { sent: false, decision: "error", reason: `evaluate failed: ${errorText(err)}`, messageDigest });
  }

  if (evalResp.decision !== "allow") {
    return blocked(options, {
      sent: false,
      decision: evalResp.decision,
      reason: evalResp.reason || `blocked by decision=${evalResp.decision}`,
      ...(evalResp.deny_code !== null ? { denyCode: evalResp.deny_code } : {}),
      evaluationId: evalResp.evaluationId,
      auditHash: evalResp.auditHash,
      messageDigest,
    });
  }

  const permitId = evalResp.permitId;
  const evidence = { evaluationId: evalResp.evaluationId, auditHash: evalResp.auditHash, messageDigest };

  let verifyResp: VerifyPermitResponse;
  try {
    // Re-present the digest the runtime signed into the permit
    // (execution_hash_expected); anything else is a PAYLOAD_MISMATCH.
    verifyResp = await atlasent.verifyPermit({
      permitId,
      agent: options.agent,
      action: COMMUNICATION_EXTERNAL_SEND,
      environment,
      execution_hash: messageDigest,
    });
  } catch (err) {
    return blocked(options, { sent: false, decision: "error", reason: `verifyPermit failed: ${errorText(err)}`, ...evidence });
  }

  if (verifyResp.verified !== true) {
    return blocked(options, {
      sent: false,
      decision: "verify_failed",
      reason: `permit verification failed: outcome=${verifyResp.outcome}`,
      ...evidence,
    });
  }
  if (verifyResp.consumed !== true) {
    // Verified but not burned (verify-only mode, or a runtime that does not
    // say): the permit could be presented again, so it cannot authorize a
    // send that must happen once.
    return blocked(options, {
      sent: false,
      decision: "verify_failed",
      reason: "permit verified but was not reported consumed",
      ...evidence,
    });
  }

  if (rereadDigest !== null) {
    let current: string;
    try {
      current = await rereadDigest();
    } catch (err) {
      return blocked(options, { sent: false, decision: "error", reason: `could not re-read the draft: ${errorText(err)}`, ...evidence });
    }
    if (current !== messageDigest) {
      return blocked(options, {
        sent: false,
        decision: "content_changed",
        reason: "the draft changed after it was authorized",
        ...evidence,
      });
    }
  }

  // ONLY reachable once evaluate returned allow AND verify confirmed and
  // consumed the permit. The single call site of the Gmail send endpoints.
  const message = await performSend();

  return { sent: true, message, permitId, auditHash: evalResp.auditHash, messageDigest };
}

async function requestApproval(
  atlasent: AtlaSentClient,
  snapshot: GmailSendSnapshot,
  facts: GmailExternalSendFacts,
  options: GmailSendGuardOptions,
): Promise<GmailSendApprovalRequest> {
  const messageDigest = await computeGmailSendDigest(snapshot);
  let evalResp: EvaluateResponse;
  try {
    // approvals: 1 with no artifact — the same request the send will make
    // once the artifact is attached, so the runtime hands out the action_hash
    // that send will be checked against (ADR-055 two-step).
    evalResp = await evaluateSend(atlasent, facts, options, messageDigest, 1, undefined);
  } catch (err) {
    return { ok: false, reason: `evaluate failed: ${errorText(err)}`, messageDigest };
  }
  if (evalResp.decision === "allow") {
    // The permit minted here is never verified or used; it expires.
    return {
      ok: false,
      decision: "allow",
      reason: "the runtime allowed this request without an approval artifact, so there is no approval to request",
      messageDigest,
    };
  }
  if (evalResp.signingHint === undefined) {
    return {
      ok: false,
      decision: evalResp.decision,
      ...(evalResp.deny_code !== null ? { denyCode: evalResp.deny_code } : {}),
      reason: evalResp.reason || "the runtime returned no signing hint for this request",
      messageDigest,
    };
  }
  return { ok: true, signingHint: evalResp.signingHint, messageDigest };
}

/**
 * Step one of the ADR-055 two-step approval for {@link guardedGmailSend}:
 * returns the `action_hash` a human approval for exactly this message must
 * sign. Sends nothing. Call the send with the same `request`, `facts` and
 * `options` plus `approvalArtifact`.
 */
export async function requestGmailSendApproval(
  atlasent: AtlaSentClient,
  request: gmail_v1.Params$Resource$Users$Messages$Send,
  facts: GmailExternalSendFacts,
  options: GmailSendGuardOptions,
): Promise<GmailSendApprovalRequest> {
  let snapshot: GmailSendSnapshot;
  try {
    snapshot = snapshotMessageRequest(request);
  } catch (err) {
    return { ok: false, reason: errorText(err) };
  }
  return requestApproval(atlasent, snapshot, facts, options);
}

/** {@link requestGmailSendApproval} for {@link guardedGmailSendDraft}: binds the draft's current content. */
export async function requestGmailSendDraftApproval(
  gmail: Pick<gmail_v1.Gmail, "users">,
  atlasent: AtlaSentClient,
  request: gmail_v1.Params$Resource$Users$Drafts$Send,
  facts: GmailExternalSendFacts,
  options: GmailSendGuardOptions,
): Promise<GmailSendApprovalRequest> {
  let snapshot: GmailSendSnapshot;
  try {
    const { userId, draftId } = draftIdOf(request);
    snapshot = await snapshotDraft(gmail, userId, draftId);
  } catch (err) {
    return { ok: false, reason: errorText(err) };
  }
  return requestApproval(atlasent, snapshot, facts, options);
}
