# `@atlasent/gmail`

AtlaSent send-time authorization gate for the Gmail API. Implements
CANON-000047 / ACT-0050 (`communication.external.send`) as a **send-time
API gate**: AtlaSent evaluates the send, and verifies and consumes the
permit, *before* the caller's own Gmail API call is ever made. A denied,
held, or unverified request never reaches Gmail.

```
1. evaluate     — check the policy engine (communication.external.send)
2. verifyPermit — confirm and consume the permit for THIS message
3. send         — call Gmail ONLY if both pass, with the bytes that were authorized
```

Zero runtime dependency on `googleapis` — it is a type-only import, so
this package works with whatever `googleapis` version you already have
installed and adds no runtime weight of its own. `@atlasent/sdk` (`^2.23.0`)
is a peer dependency, same as `@atlasent/cursor` and `@atlasent/langchain`.

## Install

```bash
npm install @atlasent/gmail @atlasent/sdk googleapis
```

## Usage

`communication.external.send` requires a verified human approval. Approval
is two steps (ADR-055): ask the runtime what an approval for this exact
message must sign, have a person review the message and sign it, then send
with the signed artifact.

```ts
import { google } from "googleapis";
import { AtlaSentClient } from "@atlasent/sdk";
import { guardedGmailSend, requestGmailSendApproval } from "@atlasent/gmail";

const gmail = google.gmail({ version: "v1", auth: oauth2Client });
const atlasent = new AtlaSentClient({ apiKey, baseUrl });

const request = { userId: "me", requestBody: { raw: encodedMimeMessage } };
const facts = {
  recipient: "newcustomer@example.com",
  recipientKnown: false,
  sensitiveAttachment: true,
  attachmentSha256: "3b1c...deadbeef",
};
const options = { agent: "user:sales-rep-01" };

// 1. What must the approval bind? Sends nothing.
const approval = await requestGmailSendApproval(atlasent, request, facts, options);
if (!approval.ok) throw new Error(approval.reason);

// 2. Your approval desk shows the message to a person, who signs
//    approval.signingHint.bind.action_hash into an approval_artifact.v1.
const approvalArtifact = await yourApprovalDesk.sign(approval);

// 3. Send — the same request, facts and options, plus the artifact.
const result = await guardedGmailSend(gmail, atlasent, request, facts, { ...options, approvalArtifact });

if (result.sent) {
  console.log("sent", result.message.id, "permit", result.permitId, "digest", result.messageDigest);
} else {
  console.log("blocked", result.decision, result.reason);
}
```

`guardedGmailSendDraft` / `requestGmailSendDraftApproval` do the same for
an existing draft sent with `gmail.users.drafts.send`.
`gmail.users.drafts.create` / `gmail.users.messages.insert` are deliberately
**not** wrapped — neither delivers mail, so neither is a
`communication.external.send` event.

## What the permit and the approval are bound to

The guard snapshots the exact request Gmail will receive — `userId`, the
base64url `raw` RFC 2822 message (recipients, headers, body and
attachments) and `threadId` — and hashes it (`computeGmailSendDigest`).
That digest is sent to `/v1-evaluate` twice:

- as top-level **`execution_payload_hash`**, which the runtime signs into
  the permit and which the guard re-presents at verify; and
- as top-level **`resource_id`**, which the runtime folds into the
  `action_hash` a human approval signs.

So an approval for one message cannot authorize another, and a permit for
one message cannot be spent on another. Gmail is called with a request built
from the snapshot, not with your object, so changing that object while the
send is being authorized changes nothing that is sent. Only `userId`, `raw`
and `threadId` are sent; other `requestBody` fields are not.

For drafts, Gmail sends the draft as Gmail holds it, so the guard reads it
(`drafts.get`, `format: "raw"`), binds those bytes, and reads it again just
before `drafts.send`. An edit after authorization blocks the send
(`content_changed`). An edit in the instant between that final read and
Gmail's own send cannot be observed from a client.

## Fail-closed guarantees

- **Deny / hold / escalate** → Gmail is never called.
- **Evaluate or verify error** → Gmail is never called (`decision: "error"`).
- **Verify returns `verified: false`** (mismatch, expired, revoked,
  replayed, malformed), **or verifies without `consumed: true`** → Gmail is
  never called (`decision: "verify_failed"`).
- **No attached approval** → the guard reports `approvals: 0`; it never
  claims an approval it does not hold.
- **A request it cannot bind** (no `raw`, no `userId`, a media upload, a
  `drafts.send` carrying replacement content) → refused before evaluate
  (`decision: "invalid_request"`).
- The Gmail send endpoints are called in exactly one place in this package's
  source (`runGuardedSend`'s final `performSend()`), reached only after all
  of the above pass.

## Options

| Option | Type | Description |
| --- | --- | --- |
| `agent` | `string` | Required. AtlaSent actor identifier for the caller (e.g. `"user:sales-rep-01"`, `"agent:outreach-assistant"`). |
| `environment` | `string` | Optional. Defaults to `"production"`. |
| `approvalArtifact` | `object` | Optional. A signed `approval_artifact.v1` for this message, sent as `approval.artifact`. |
| `extraContext` | `object` | Optional. Extra context merged into the evaluate call; the guard's own fields win. Pass the same value to the approval request and the send. |
| `onDeny` | `"result"` (default) \| `"throw"` | `"result"` returns a `GmailSendDenial`; `"throw"` raises `GmailSendDeniedError`. |

## Upgrading from 0.1.0

- `GmailExternalSendFacts.approvals` is ignored. Attach `approvalArtifact`
  instead; obtain what it must sign from `requestGmailSendApproval`.
- 0.1.0 could not complete a send: its verify digest never matched the
  runtime's binding, so every call ended `verify_failed`.
- Requests must carry `requestBody.raw`; media uploads are refused.

## What this package does NOT decide

- **The classification facts** (`recipient`, recipient-known status,
  attachment hash, sensitivity) are your assertions, used as policy inputs.
  This package does not parse MIME, so it does not check them against the
  bytes. The approval covers the bytes and the facts together, which is why
  the person approving should see the message.
- **Other paths to Gmail.** The gate holds only where it is the agent's only
  route to sending. An agent that also holds a Gmail credential with
  `gmail.send`, or a raw Gmail tool, can send without it.
- **OAuth client setup and scopes.** You authenticate the `gmail_v1.Gmail`
  client you pass in (this package never touches Google credentials).
  `users.messages.send` needs `gmail.send`; the draft path needs
  `gmail.compose`, which covers `drafts.get` and `drafts.send`.

## Testing

This package has never been exercised against a live Gmail/Workspace
account — there is no fixture for that in this repository, and none is
fabricated. `test/guard.test.ts` drives the real `AtlaSentClient` against a
fake runtime that applies the runtime's binding, approval and consume rules,
with a recording Gmail mock. CI: `.github/workflows/gmail-ci.yml`.
