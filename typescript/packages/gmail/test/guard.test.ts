/**
 * @atlasent/gmail against a fake runtime that enforces what the real one does.
 *
 * The 0.1.0 suite stubbed `AtlaSentClient` outright, so it could not see
 * that the guard presented a verify digest no runtime would ever accept, or
 * that a caller-typed `approvals` count was sent as evidence. Every test here
 * drives the REAL `AtlaSentClient` from `@atlasent/sdk` over a fake `fetch`
 * that applies the runtime's rules:
 *
 *   - the permit binds top-level `execution_payload_hash` when it is bare hex,
 *     else `"sha256:" +` a hash of the whole posted body;
 *   - verify compares the presented `payload_hash ?? execution_hash` with it,
 *     and burns the permit (`consumed: true`) on success;
 *   - a human approval verifies only if `approval.artifact.action_hash` equals
 *     the hash of {action_type, actor_id, resource_id, context, environment},
 *     once per nonce; with no artifact the deny carries that hash as
 *     `signing_hint`.
 *
 * No test touches a real Gmail account: `gmail` is a recording mock.
 */

import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { AtlaSentClient } from "@atlasent/sdk";
import type { gmail_v1 } from "googleapis";
import {
  guardedGmailSend,
  guardedGmailSendDraft,
  requestGmailSendApproval,
  requestGmailSendDraftApproval,
  computeExternalSendTargetId,
  computeGmailSendDigest,
  GmailSendDeniedError,
  COMMUNICATION_EXTERNAL_SEND,
  type GmailExternalSendFacts,
  type GmailSendSnapshot,
} from "../src/index.js";

// ── fake runtime ─────────────────────────────────────────────────────────────

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

const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

interface RuntimeOptions {
  /** The action class demands a verified artifact (the seeded default). */
  requireArtifact?: boolean;
  /** What a successful verify reports as `consumed`. `null` omits the field. */
  consumed?: boolean | null;
  /** Fail the evaluate / verify transport. */
  evaluateThrows?: boolean;
  verifyThrows?: boolean;
  /** Return this decision outright (e.g. "hold"). */
  forceDecision?: string;
  /** Called after evaluate has answered, before the guard verifies. */
  afterEvaluate?: () => void;
  /** Called after verify has answered, before the guard sends. */
  afterVerify?: () => void;
}

function fakeRuntime(opts: RuntimeOptions = {}) {
  const evaluateBodies: Record<string, unknown>[] = [];
  const verifyBodies: Record<string, unknown>[] = [];
  const permits = new Map<string, { bound: string; consumed: boolean }>();
  const usedNonces = new Set<string>();
  let seq = 0;

  function actionHash(body: Record<string, unknown>): string {
    return sha256(
      JSON.stringify(
        sortKeysDeep({
          action_type: body.action_type,
          actor_id: body.actor_id,
          resource_id: typeof body.resource_id === "string" ? body.resource_id : "",
          context: body.context ?? {},
          environment: body.environment ?? null,
        }),
      ),
    );
  }

  function evaluate(body: Record<string, unknown>) {
    evaluateBodies.push(body);
    if (opts.evaluateThrows) throw new Error("connect ECONNREFUSED");
    if (opts.forceDecision) return { decision: opts.forceDecision, reason: "forced", request_id: "req-forced" };
    const hash = actionHash(body);
    const artifact = (body.approval as { artifact?: Record<string, unknown> } | undefined)?.artifact;
    let approved = false;
    if (artifact !== undefined) {
      const nonce = String(artifact.nonce);
      if (artifact.action_hash !== hash) {
        return { decision: "deny", deny_code: "APPROVAL_INVALID", deny_reason: "approval does not match this action" };
      }
      if (usedNonces.has(nonce)) {
        return { decision: "deny", deny_code: "APPROVAL_REPLAYED", deny_reason: "approval already used" };
      }
      usedNonces.add(nonce);
      approved = true;
    }
    const approvals = (body.context as Record<string, unknown>).approvals as number;
    const allowed = opts.requireArtifact === false ? approvals >= 1 : approved;
    if (!allowed) {
      return {
        decision: "deny",
        deny_code: "INSUFFICIENT_APPROVALS",
        deny_reason: "a human approval is required",
        request_id: `req-${++seq}`,
        ...(artifact === undefined && {
          signing_hint: {
            assertion_type: "approval_artifact.v1",
            bind: { action_hash: hash, tenant_id: "org-1", environment: String(body.environment) },
          },
        }),
      };
    }
    const epHash = body.execution_payload_hash;
    const bound =
      typeof epHash === "string" && /^[0-9a-f]{64}$/i.test(epHash)
        ? epHash.toLowerCase()
        : "sha256:" + sha256(JSON.stringify(sortKeysDeep(body)));
    const token = `pt.v3.fake-${++seq}`;
    permits.set(token, { bound, consumed: false });
    return { decision: "allow", permit_token: token, request_id: `req-${seq}`, audit_hash: `audit-${seq}` };
  }

  function verify(body: Record<string, unknown>) {
    verifyBodies.push(body);
    if (opts.verifyThrows) throw new Error("socket hang up");
    const permit = permits.get(String(body.permit_token));
    if (!permit) return { valid: false, outcome: "deny", verify_error_code: "PERMIT_NOT_FOUND" };
    if (permit.consumed) return { valid: false, outcome: "deny", verify_error_code: "PERMIT_ALREADY_USED", consumed: false };
    const presented = body.payload_hash ?? body.execution_hash;
    if (presented !== permit.bound) {
      return { valid: false, outcome: "deny", verify_error_code: "PAYLOAD_MISMATCH", consumed: false };
    }
    permit.consumed = true;
    return {
      valid: true,
      outcome: "allow",
      ...(opts.consumed === null ? {} : { consumed: opts.consumed ?? true }),
    };
  }

  const fetch = vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
    const reply = url.endsWith("/v1-evaluate") ? evaluate(body) : url.endsWith("/v1-verify-permit") ? verify(body) : null;
    if (reply === null) throw new Error(`unexpected request ${url}`);
    if (url.endsWith("/v1-evaluate")) opts.afterEvaluate?.();
    if (url.endsWith("/v1-verify-permit")) opts.afterVerify?.();
    return new Response(JSON.stringify(reply), { status: 200, headers: { "Content-Type": "application/json" } });
  }) as unknown as typeof globalThis.fetch;

  const client = new AtlaSentClient({ apiKey: "ask_live_test", fetch, retryPolicy: { maxAttempts: 1 } });
  return { client, evaluateBodies, verifyBodies };
}

/** What a human approval desk produces once a person has reviewed the message. */
function signFor(hint: { bind: { action_hash: string } }, nonce = "nonce-1"): Record<string, unknown> {
  return { version: "approval_artifact.v1", action_hash: hint.bind.action_hash, nonce };
}

// ── fake Gmail ───────────────────────────────────────────────────────────────

function makeGmail(draftRaw = "RFC822-draft-original") {
  const draft = { raw: draftRaw, threadId: "thread-d" as string | undefined };
  const users = {
    messages: { send: vi.fn(async (_req: unknown) => ({ data: { id: "msg-1", threadId: "thread-1" } })) },
    drafts: {
      get: vi.fn(async (_req: unknown) => ({ data: { id: "draft-1", message: { raw: draft.raw, threadId: draft.threadId } } })),
      send: vi.fn(async (_req: unknown) => ({ data: { id: "msg-draft-1" } })),
    },
  };
  return { gmail: { users } as unknown as Pick<gmail_v1.Gmail, "users">, users, draft };
}

// ── fixtures ─────────────────────────────────────────────────────────────────

const FACTS: GmailExternalSendFacts = {
  recipient: "newcustomer@example.com",
  recipientKnown: false,
  sensitiveAttachment: true,
  attachmentSha256: "3b1c0000deadbeef",
  actorOrigin: "human",
};
const OPTIONS = { agent: "user:sales-rep-01" };

function messageRequest(raw = "RFC822-A") {
  return { userId: "me", requestBody: { raw, threadId: "thread-1", labelIds: ["INBOX"] } };
}

async function approvedArtifact(client: AtlaSentClient, raw = "RFC822-A", nonce = "nonce-1") {
  const approval = await requestGmailSendApproval(client, messageRequest(raw), FACTS, OPTIONS);
  if (!approval.ok) throw new Error(`approval request failed: ${approval.reason}`);
  return signFor(approval.signingHint, nonce);
}

// ── messages.send ────────────────────────────────────────────────────────────

describe("guardedGmailSend: the two-step approval sends exactly the approved message", () => {
  it("approval request, signed artifact, then exactly one send of the snapshot", async () => {
    const { client, verifyBodies } = fakeRuntime();
    const { gmail, users } = makeGmail();
    const artifact = await approvedArtifact(client);

    const result = await guardedGmailSend(gmail, client, messageRequest(), FACTS, { ...OPTIONS, approvalArtifact: artifact });

    expect(result.sent).toBe(true);
    expect(users.messages.send).toHaveBeenCalledTimes(1);
    // Only the bound fields are sent; labelIds and anything else are not.
    expect(users.messages.send).toHaveBeenCalledWith({ userId: "me", requestBody: { raw: "RFC822-A", threadId: "thread-1" } });
    if (result.sent) {
      expect(result.messageDigest).toBe(verifyBodies[0]!.execution_hash);
    }
  });

  it("the approval request and the send present the same evaluate body apart from the artifact", async () => {
    const { client, evaluateBodies } = fakeRuntime();
    const { gmail } = makeGmail();
    const artifact = await approvedArtifact(client);
    await guardedGmailSend(gmail, client, messageRequest(), FACTS, { ...OPTIONS, approvalArtifact: artifact });

    const [harvest, submit] = evaluateBodies;
    expect(harvest!.approval).toBeUndefined();
    expect(submit!.approval).toEqual({ artifact });
    const { approval: _a, ...rest } = submit!;
    expect(rest).toEqual(harvest);
  });

  it("binds the message: execution_payload_hash, resource_id and the verify digest are all the snapshot digest", async () => {
    const { client, evaluateBodies, verifyBodies } = fakeRuntime();
    const { gmail } = makeGmail();
    const artifact = await approvedArtifact(client);
    await guardedGmailSend(gmail, client, messageRequest(), FACTS, { ...OPTIONS, approvalArtifact: artifact });

    const expected = await computeGmailSendDigest({
      kind: "message",
      userId: "me",
      raw: "RFC822-A",
      threadId: "thread-1",
      draftId: null,
    });
    const submit = evaluateBodies[1]!;
    expect(submit.execution_payload_hash).toBe(expected);
    expect(submit.resource_id).toBe(expected);
    expect(verifyBodies[0]!.execution_hash).toBe(expected);
    expect((submit.context as Record<string, unknown>).execution_payload_hash).toBeUndefined();
  });

  it("an approval for one message does not authorize another to the same recipient", async () => {
    const { client } = fakeRuntime();
    const { gmail, users } = makeGmail();
    const artifactForA = await approvedArtifact(client, "RFC822-A");

    const result = await guardedGmailSend(gmail, client, messageRequest("RFC822-B"), FACTS, {
      ...OPTIONS,
      approvalArtifact: artifactForA,
    });

    expect(result.sent).toBe(false);
    if (!result.sent) expect(result.denyCode).toBe("APPROVAL_INVALID");
    expect(users.messages.send).not.toHaveBeenCalled();
  });

  it("sends the snapshot even if the caller mutates its request while authorization is in flight", async () => {
    const request = messageRequest("RFC822-A");
    const { client } = fakeRuntime({ afterVerify: () => (request.requestBody.raw = "RFC822-SWAPPED") });
    const { gmail, users } = makeGmail();
    const artifact = await approvedArtifact(client);

    const result = await guardedGmailSend(gmail, client, request, FACTS, { ...OPTIONS, approvalArtifact: artifact });

    expect(result.sent).toBe(true);
    expect(users.messages.send).toHaveBeenCalledWith({ userId: "me", requestBody: { raw: "RFC822-A", threadId: "thread-1" } });
  });

  it("the same artifact cannot authorize a second send", async () => {
    const { client } = fakeRuntime();
    const { gmail, users } = makeGmail();
    const artifact = await approvedArtifact(client);
    const options = { ...OPTIONS, approvalArtifact: artifact };

    expect((await guardedGmailSend(gmail, client, messageRequest(), FACTS, options)).sent).toBe(true);
    const second = await guardedGmailSend(gmail, client, messageRequest(), FACTS, options);

    expect(second.sent).toBe(false);
    expect(users.messages.send).toHaveBeenCalledTimes(1);
  });
});

describe("guardedGmailSend: approvals are not caller claims", () => {
  it("without an artifact the guard reports zero approvals and nothing is sent", async () => {
    const { client, evaluateBodies } = fakeRuntime();
    const { gmail, users } = makeGmail();

    const result = await guardedGmailSend(gmail, client, messageRequest(), FACTS, OPTIONS);

    expect(result.sent).toBe(false);
    if (!result.sent) expect(result.denyCode).toBe("INSUFFICIENT_APPROVALS");
    expect((evaluateBodies[0]!.context as Record<string, unknown>).approvals).toBe(0);
    expect(evaluateBodies[0]!.approval).toBeUndefined();
    expect(users.messages.send).not.toHaveBeenCalled();
  });

  it("a deprecated facts.approvals count is ignored, even where the class does not demand an artifact", async () => {
    // requireArtifact: false models an org whose class would accept the
    // context count alone, which is what 0.1.0 let a caller type in.
    const { client, evaluateBodies } = fakeRuntime({ requireArtifact: false });
    const { gmail, users } = makeGmail();

    const result = await guardedGmailSend(gmail, client, messageRequest(), { ...FACTS, approvals: 5 }, OPTIONS);

    expect(result.sent).toBe(false);
    expect((evaluateBodies[0]!.context as Record<string, unknown>).approvals).toBe(0);
    expect(users.messages.send).not.toHaveBeenCalled();
  });

  it("extraContext cannot override the guard's own fields", async () => {
    const { client, evaluateBodies } = fakeRuntime();
    const { gmail } = makeGmail();

    await guardedGmailSend(gmail, client, messageRequest(), FACTS, {
      ...OPTIONS,
      extraContext: { approvals: 9, recipient_known: true, sensitive_attachment: false, tenant: "acme" },
    });

    const context = evaluateBodies[0]!.context as Record<string, unknown>;
    expect(context.approvals).toBe(0);
    expect(context.recipient_known).toBe(false);
    expect(context.sensitive_attachment).toBe(true);
    expect(context.tenant).toBe("acme");
  });

  it("AI-agent-originated and human-originated sends are denied identically on the same shortfall", async () => {
    const human = fakeRuntime();
    const agent = fakeRuntime();
    const { gmail } = makeGmail();
    const h = await guardedGmailSend(gmail, human.client, messageRequest(), { ...FACTS, actorOrigin: "human" }, OPTIONS);
    const a = await guardedGmailSend(gmail, agent.client, messageRequest(), { ...FACTS, actorOrigin: "ai_agent" }, OPTIONS);
    expect(h.sent).toBe(false);
    expect(a.sent).toBe(false);
    if (!h.sent && !a.sent) expect(a.denyCode).toBe(h.denyCode);
  });
});

describe("guardedGmailSend: fails closed", () => {
  it("never sends on a hold", async () => {
    const { client } = fakeRuntime({ forceDecision: "hold" });
    const { gmail, users } = makeGmail();
    const result = await guardedGmailSend(gmail, client, messageRequest(), FACTS, OPTIONS);
    expect(result.sent).toBe(false);
    if (!result.sent) expect(result.decision).toBe("hold");
    expect(users.messages.send).not.toHaveBeenCalled();
  });

  it("never sends when evaluate fails", async () => {
    const { client } = fakeRuntime({ evaluateThrows: true });
    const { gmail, users } = makeGmail();
    const result = await guardedGmailSend(gmail, client, messageRequest(), FACTS, OPTIONS);
    expect(result.sent).toBe(false);
    if (!result.sent) expect(result.decision).toBe("error");
    expect(users.messages.send).not.toHaveBeenCalled();
  });

  it("never sends when verify fails in transport", async () => {
    const runtime = fakeRuntime();
    const { gmail, users } = makeGmail();
    const artifact = await approvedArtifact(runtime.client);
    const failing = fakeRuntime({ verifyThrows: true });
    // Re-sign against the failing runtime's evaluate, which hashes identically.
    const result = await guardedGmailSend(gmail, failing.client, messageRequest(), FACTS, {
      ...OPTIONS,
      approvalArtifact: artifact,
    });
    expect(result.sent).toBe(false);
    if (!result.sent) expect(result.decision).toBe("error");
    expect(users.messages.send).not.toHaveBeenCalled();
  });

  it.each([
    ["reported unconsumed", false],
    ["not reported", null],
  ] as const)("never sends when the permit verified but was %s consumed", async (_label, consumed) => {
    const { client } = fakeRuntime({ consumed });
    const { gmail, users } = makeGmail();
    const artifact = await approvedArtifact(client);
    const result = await guardedGmailSend(gmail, client, messageRequest(), FACTS, { ...OPTIONS, approvalArtifact: artifact });
    expect(result.sent).toBe(false);
    if (!result.sent) expect(result.reason).toContain("not reported consumed");
    expect(users.messages.send).not.toHaveBeenCalled();
  });

  it.each([
    ["no raw message", { userId: "me", requestBody: {} }],
    ["an empty raw message", { userId: "me", requestBody: { raw: "" } }],
    ["no userId", { requestBody: { raw: "RFC822-A" } }],
    ["a media upload", { userId: "me", requestBody: { raw: "RFC822-A" }, media: { mimeType: "message/rfc822", body: "x" } }],
  ])("refuses %s before evaluating", async (_label, request) => {
    const { client, evaluateBodies } = fakeRuntime();
    const { gmail, users } = makeGmail();
    const result = await guardedGmailSend(gmail, client, request as gmail_v1.Params$Resource$Users$Messages$Send, FACTS, OPTIONS);
    expect(result.sent).toBe(false);
    if (!result.sent) expect(result.decision).toBe("invalid_request");
    expect(evaluateBodies).toHaveLength(0);
    expect(users.messages.send).not.toHaveBeenCalled();
  });

  it("throws GmailSendDeniedError when onDeny is 'throw'", async () => {
    const { client } = fakeRuntime();
    const { gmail, users } = makeGmail();
    await expect(
      guardedGmailSend(gmail, client, messageRequest(), FACTS, { ...OPTIONS, onDeny: "throw" }),
    ).rejects.toBeInstanceOf(GmailSendDeniedError);
    expect(users.messages.send).not.toHaveBeenCalled();
  });
});

describe("requestGmailSendApproval", () => {
  it("returns the runtime's signing hint and the message digest, and sends nothing", async () => {
    const { client, evaluateBodies } = fakeRuntime();
    const result = await requestGmailSendApproval(client, messageRequest(), FACTS, OPTIONS);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.signingHint.bind.action_hash).toMatch(/^[0-9a-f]{64}$/);
      expect(result.messageDigest).toBe(evaluateBodies[0]!.resource_id);
    }
    expect((evaluateBodies[0]!.context as Record<string, unknown>).approvals).toBe(1);
  });

  it("reports an allow without an artifact instead of returning a hint", async () => {
    const { client } = fakeRuntime({ requireArtifact: false });
    const result = await requestGmailSendApproval(client, messageRequest(), FACTS, OPTIONS);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.decision).toBe("allow");
  });

  it("reports a deny without a hint", async () => {
    const { client } = fakeRuntime({ forceDecision: "deny" });
    const result = await requestGmailSendApproval(client, messageRequest(), FACTS, OPTIONS);
    expect(result.ok).toBe(false);
  });

  it("reports an evaluate failure and a malformed request", async () => {
    expect((await requestGmailSendApproval(fakeRuntime({ evaluateThrows: true }).client, messageRequest(), FACTS, OPTIONS)).ok).toBe(false);
    expect((await requestGmailSendApproval(fakeRuntime().client, { userId: "me" }, FACTS, OPTIONS)).ok).toBe(false);
  });
});

// ── drafts.send ──────────────────────────────────────────────────────────────

const DRAFT_REQUEST = { userId: "me", requestBody: { id: "draft-1" } };

async function approvedDraftArtifact(client: AtlaSentClient, gmail: Pick<gmail_v1.Gmail, "users">) {
  const approval = await requestGmailSendDraftApproval(gmail, client, DRAFT_REQUEST, FACTS, OPTIONS);
  if (!approval.ok) throw new Error(`approval request failed: ${approval.reason}`);
  return signFor(approval.signingHint);
}

describe("guardedGmailSendDraft", () => {
  it("binds the draft's current content and sends it by id once approved", async () => {
    const { client, evaluateBodies } = fakeRuntime();
    const { gmail, users } = makeGmail("RFC822-draft-original");
    const artifact = await approvedDraftArtifact(client, gmail);

    const result = await guardedGmailSendDraft(gmail, client, DRAFT_REQUEST, FACTS, { ...OPTIONS, approvalArtifact: artifact });

    expect(result.sent).toBe(true);
    expect(users.drafts.send).toHaveBeenCalledTimes(1);
    expect(users.drafts.send).toHaveBeenCalledWith({ userId: "me", requestBody: { id: "draft-1" } });
    expect(users.drafts.get).toHaveBeenCalledWith({ userId: "me", id: "draft-1", format: "raw" });
    const expected = await computeGmailSendDigest({
      kind: "draft",
      userId: "me",
      raw: "RFC822-draft-original",
      threadId: "thread-d",
      draftId: "draft-1",
    });
    expect(evaluateBodies[1]!.resource_id).toBe(expected);
  });

  it("an edit after the approval was requested makes the approval not match", async () => {
    const { client } = fakeRuntime();
    const { gmail, users, draft } = makeGmail();
    const artifact = await approvedDraftArtifact(client, gmail);
    draft.raw = "RFC822-draft-edited";

    const result = await guardedGmailSendDraft(gmail, client, DRAFT_REQUEST, FACTS, { ...OPTIONS, approvalArtifact: artifact });

    expect(result.sent).toBe(false);
    expect(users.drafts.send).not.toHaveBeenCalled();
  });

  it("an edit after authorization refuses the send", async () => {
    const holder: { draft?: { raw: string } } = {};
    const { client } = fakeRuntime({ afterVerify: () => holder.draft && (holder.draft.raw = "RFC822-draft-edited") });
    const { gmail, users, draft } = makeGmail();
    const artifact = await approvedDraftArtifact(client, gmail);
    holder.draft = draft;

    const result = await guardedGmailSendDraft(gmail, client, DRAFT_REQUEST, FACTS, { ...OPTIONS, approvalArtifact: artifact });

    expect(result.sent).toBe(false);
    if (!result.sent) expect(result.decision).toBe("content_changed");
    expect(users.drafts.send).not.toHaveBeenCalled();
  });

  it("never sends the draft without an approval", async () => {
    const { client } = fakeRuntime();
    const { gmail, users } = makeGmail();
    const result = await guardedGmailSendDraft(gmail, client, DRAFT_REQUEST, FACTS, OPTIONS);
    expect(result.sent).toBe(false);
    expect(users.drafts.send).not.toHaveBeenCalled();
  });

  it.each([
    ["replacement message content", { userId: "me", requestBody: { id: "draft-1", message: { raw: "other" } } }],
    ["a media upload", { userId: "me", requestBody: { id: "draft-1" }, media: { mimeType: "message/rfc822", body: "x" } }],
    ["no draft id", { userId: "me", requestBody: {} }],
    ["no userId", { requestBody: { id: "draft-1" } }],
  ])("refuses %s before evaluating", async (_label, request) => {
    const { client, evaluateBodies } = fakeRuntime();
    const { gmail, users } = makeGmail();
    const result = await guardedGmailSendDraft(gmail, client, request as gmail_v1.Params$Resource$Users$Drafts$Send, FACTS, OPTIONS);
    expect(result.sent).toBe(false);
    if (!result.sent) expect(result.decision).toBe("invalid_request");
    expect(evaluateBodies).toHaveLength(0);
    expect(users.drafts.send).not.toHaveBeenCalled();
  });

  it("refuses a draft it cannot read, or one with no content", async () => {
    const { client } = fakeRuntime();
    const unreadable = makeGmail();
    unreadable.users.drafts.get.mockRejectedValueOnce(new Error("404"));
    const r1 = await guardedGmailSendDraft(unreadable.gmail, client, DRAFT_REQUEST, FACTS, OPTIONS);
    expect(r1.sent).toBe(false);
    if (!r1.sent) expect(r1.decision).toBe("error");

    const empty = makeGmail("");
    const r2 = await guardedGmailSendDraft(empty.gmail, client, DRAFT_REQUEST, FACTS, OPTIONS);
    expect(r2.sent).toBe(false);
    if (!r2.sent) expect(r2.decision).toBe("invalid_request");
    expect(unreadable.users.drafts.send).not.toHaveBeenCalled();
    expect(empty.users.drafts.send).not.toHaveBeenCalled();
  });

  it("refuses when the pre-send re-read fails", async () => {
    const { client } = fakeRuntime();
    const { gmail, users } = makeGmail();
    const artifact = await approvedDraftArtifact(client, gmail);
    users.drafts.get.mockImplementationOnce(async () => ({ data: { id: "draft-1", message: { raw: "RFC822-draft-original", threadId: "thread-d" } } }));
    users.drafts.get.mockRejectedValueOnce(new Error("503"));

    const result = await guardedGmailSendDraft(gmail, client, DRAFT_REQUEST, FACTS, { ...OPTIONS, approvalArtifact: artifact });

    expect(result.sent).toBe(false);
    if (!result.sent) expect(result.decision).toBe("error");
    expect(users.drafts.send).not.toHaveBeenCalled();
  });
});

// ── digests ──────────────────────────────────────────────────────────────────

describe("computeGmailSendDigest", () => {
  const BASE: GmailSendSnapshot = { kind: "message", userId: "me", raw: "RFC822-A", threadId: "t", draftId: null };

  it("is a deterministic 64-char lowercase hex digest", async () => {
    const d = await computeGmailSendDigest(BASE);
    expect(d).toMatch(/^[0-9a-f]{64}$/);
    expect(await computeGmailSendDigest({ ...BASE })).toBe(d);
  });

  it.each([
    ["raw", { raw: "RFC822-B" }],
    ["userId", { userId: "other@example.com" }],
    ["threadId", { threadId: null }],
    ["kind", { kind: "draft" as const, draftId: "d" }],
  ])("changes with %s", async (_label, change) => {
    expect(await computeGmailSendDigest({ ...BASE, ...change })).not.toBe(await computeGmailSendDigest(BASE));
  });
});

describe("computeExternalSendTargetId", () => {
  it("is deterministic and changes with each binding fact", async () => {
    const base = await computeExternalSendTargetId(FACTS);
    expect(base).toMatch(/^[0-9a-f]{64}$/);
    expect(await computeExternalSendTargetId({ ...FACTS })).toBe(base);
    expect(await computeExternalSendTargetId({ ...FACTS, recipient: "other@example.com" })).not.toBe(base);
    expect(await computeExternalSendTargetId({ ...FACTS, attachmentSha256: "ffff" })).not.toBe(base);
    expect(await computeExternalSendTargetId({ ...FACTS, sensitiveAttachment: false })).not.toBe(base);
  });
});

it("uses the canonical action type", () => {
  expect(COMMUNICATION_EXTERNAL_SEND).toBe("communication.external.send");
});

// The same values are pinned by python/tests/test_gmail_guard.py, so the digest
// an approval desk shows does not depend on which SDK prepared the send. A change
// to either serialization fails one of the two suites.
describe("digest parity with the Python SDK (atlasent.gmail)", () => {
  const vectors: Array<[GmailSendSnapshot, string]> = [
    [
      { kind: "message", userId: "me", raw: "VG86IGJvYXJkQGV4YW1wbGUuY29tDQpTdWJqZWN0OiBRMw0KDQpEcmFmdA", threadId: null, draftId: null },
      "e0348537ec616f8d51a59ef95fc10c563ce576cd3507abd3c1a0d48aed101660",
    ],
    [
      { kind: "message", userId: "founder@example.com", raw: "VG86IGNmb0BleGFtcGxlLmNvbQ0KDQpoaQ", threadId: "18c2f0a1b2c3d4e5", draftId: null },
      "5ee70358999964889bb3efe9e533b87c8809e71fad72430b178540535f9bf2a3",
    ],
    [
      { kind: "draft", userId: "me", raw: "VG86IGJvYXJkQGV4YW1wbGUuY29tDQoNCkRyYWZ0IG9ubHk", threadId: null, draftId: "r-4815162342" },
      "9a443373dc4ff153cf2a6b783d7078a6751b4e26a6d83dd599fbf49d87153696",
    ],
    [
      { kind: "message", userId: "josé@exämple.com", raw: "eA", threadId: null, draftId: null },
      "3a6d95f5779e323e04d0fe7873f16688556d40a496f6bcdb95aa7a8528519d7e",
    ],
  ];
  it.each(vectors)("message digest %#", async (snapshot, expected) => {
    expect(await computeGmailSendDigest(snapshot)).toBe(expected);
  });

  it("target id", async () => {
    expect(
      await computeExternalSendTargetId({
        recipient: "board@example.com",
        recipientKnown: false,
        sensitiveAttachment: true,
        attachmentSha256: "3b".repeat(32),
      }),
    ).toBe("c20d7c236a4dfac7def7ba35e08e98a365991dc1faf5a4b2bf2227abb3fc9553");
    expect(
      await computeExternalSendTargetId({ recipient: "cfo@example.com", recipientKnown: true, sensitiveAttachment: false }),
    ).toBe("521c91f2b7887268fe8bee8d4de123ddebc2c4632e67e121a24e4a1862fb4f48");
  });
});
