# Pillar 8 — Temporal Bulk Permit Revocation: Server Implementation Spec (historical filename)

> **Reframing normalization header (2026-05-18).** Per
> the internal `VERSIONING_DOCTRINE.md`,
> the platform-generation `v2 / v3` framing has been retired. This
> spec describes additive Temporal-integration tooling on top of the
> stable **AtlaSent v1** contract; sequence it as **Phase 1 — Pilot
> Readiness** (Temporal bulk-revoke is part of the Temporal-preview
> SDK capability set). The endpoint path (`POST /v2/permits:bulk-revoke`),
> schema directory (`contract/schemas/v2/`), OpenAPI artifact
> (`contract/openapi-v2.yaml`), and SDK package names
> (`@atlasent/temporal-preview`, `atlasent-temporal-preview`) are
> **code-level identifiers** — they are schema-history artifacts
> (Doctrine 3) and published-package identifiers (Doctrine 5) and are
> preserved as-is. The public wire surface for the stable contract is
> `/v1/*` per Doctrine 3; the `/v2/permits:bulk-revoke` path here is an
> internal-build identifier in the current schema, not a public v2
> namespace.

**Status:** ready to implement
**Endpoint:** `POST /v2/permits:bulk-revoke` (code-level path; see header above)
**Contract:** `contract/schemas/v2/bulk-revoke-{request,response}.schema.json`
**OpenAPI:** `contract/openapi-v2.yaml` — `bulkRevokePermits` operation
**SDK activity:** `@atlasent/temporal-preview` / `atlasent-temporal-preview`

---

## Overview

When a Temporal workflow receives a `revokeAtlaSentPermits` signal, the
SDK's `bulkRevokeAtlaSentPermits` activity calls this endpoint. The
server locates every active permit whose `_atlasent_temporal.run_id`
context field matches the supplied `run_id` (scoped to the org derived
from `api_key`) and immediately invalidates them. This closes the entire
permit set for a workflow run in one atomic call rather than tracking
individual permit IDs on the caller side.

A call with no matching permits returns `revoked_count: 0` and HTTP 200
— this is **not an error**. It is the expected outcome when permits have
already expired or been consumed before the revoke signal fires (common
in long-running workflows).

---

## Wire contract

### Request — `POST /v2/permits:bulk-revoke`

```json
{
  "workflow_id": "deploy-prod-2026-04-29",
  "run_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "reason": "Workflow completed — permits no longer needed",
  "revoker_id": "deploy-bot",
  "api_key": "ask_live_..."
}
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `workflow_id` | string | ✓ | Temporal workflow ID. Used in audit log; **not** the primary revoke key. |
| `run_id` | UUID string | ✓ | Temporal run ID. Primary revoke key — revoke all permits with `context._atlasent_temporal.run_id == run_id`. |
| `reason` | string (1–1024 chars) | ✓ | Human-readable reason. Written to audit log and `revoked` SSE event. |
| `revoker_id` | string | — | Optional actor. Defaults to `workflow_id` in the audit log if omitted. |
| `api_key` | string | ✓ | Org-scoping key, same semantics as `/v1-evaluate`. |

### Response — 200

```json
{
  "revoked_count": 3,
  "workflow_id": "deploy-prod-2026-04-29",
  "run_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

`revoked_count: 0` is valid and not retried by the SDK.

---

## Database requirements

### Prerequisite: temporal context column on permits

Every permit issued while a Temporal workflow is active carries
`_atlasent_temporal` in its `context` JSON:

```json
{
  "context": {
    "_atlasent_temporal": {
      "workflow_id": "deploy-prod-2026-04-29",
      "run_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    }
  }
}
```

The SDK injects this via `TemporalPermitContext` before calling
`protect()`. The server stores it verbatim in the `permits.context`
column.

### Index required

```sql
-- GIN index on context JSONB for run_id lookups.
-- Without this, revoke scans the full permits table per call.
CREATE INDEX IF NOT EXISTS idx_permits_temporal_run_id
  ON permits USING gin (
    (context -> '_atlasent_temporal')
  );
```

Or a computed column + btree index if your permits table is large:

```sql
ALTER TABLE permits
  ADD COLUMN IF NOT EXISTS temporal_run_id TEXT
    GENERATED ALWAYS AS (
      context #>> '{_atlasent_temporal,run_id}'
    ) STORED;

CREATE INDEX IF NOT EXISTS idx_permits_temporal_run_id_btree
  ON permits (org_id, temporal_run_id)
  WHERE temporal_run_id IS NOT NULL AND status = 'active';
```

---

## Implementation (Supabase edge function)

File: `supabase/functions/v2-bulk-revoke/index.ts`

### Authentication

Reuse the existing `validateApiKey(req)` helper from `lib/auth.ts`.
Returns `{ orgId, keyId }` on success; throws with `invalid_api_key` on
failure.

### Core logic

```typescript
import { serve } from "https://deno.land/std/http/server.ts";
import { supabaseAdmin } from "../lib/supabase.ts";
import { validateApiKey } from "../lib/auth.ts";
import { emitDecisionEvent } from "../lib/sse.ts";

serve(async (req) => {
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ message: "Method not allowed" }), {
      status: 405,
    });
  }

  // 1. Auth
  let orgId: string, keyId: string;
  try {
    ({ orgId, keyId } = await validateApiKey(req));
  } catch {
    return errorResponse(401, "invalid_api_key", "Invalid or missing API key");
  }

  // 2. Parse and validate body
  let body: BulkRevokeRequest;
  try {
    body = await req.json();
  } catch {
    return errorResponse(400, "bad_request", "Request body must be valid JSON");
  }

  const { workflow_id, run_id, reason, revoker_id } = body;
  if (!workflow_id || typeof workflow_id !== "string") {
    return errorResponse(400, "bad_request", "workflow_id is required");
  }
  if (!run_id || !UUID_RE.test(run_id)) {
    return errorResponse(400, "bad_request", "run_id must be a UUID");
  }
  if (!reason || typeof reason !== "string" || reason.length > 1024) {
    return errorResponse(400, "bad_request", "reason is required (max 1024 chars)");
  }

  // 3. Find active permits for this run_id in this org
  const { data: permits, error: fetchErr } = await supabaseAdmin
    .from("permits")
    .select("id, context")
    .eq("org_id", orgId)
    .eq("status", "active")
    .eq("context->_atlasent_temporal->>run_id", run_id);

  if (fetchErr) {
    console.error("permits fetch failed", fetchErr);
    return errorResponse(500, "server_error", "Failed to query permits");
  }

  if (!permits || permits.length === 0) {
    // Not an error — permits may have already expired or been consumed.
    return successResponse({ revoked_count: 0, workflow_id, run_id }, req);
  }

  const permitIds = permits.map((p) => p.id);
  const revokedAt = new Date().toISOString();
  const effectiveRevokerId = revoker_id ?? workflow_id;

  // 4. Atomically revoke all matching permits
  const { error: updateErr } = await supabaseAdmin
    .from("permits")
    .update({
      status: "revoked",
      revoked_at: revokedAt,
      revoked_reason: reason,
      revoked_by: effectiveRevokerId,
    })
    .in("id", permitIds)
    .eq("org_id", orgId)      // belt-and-suspenders org scope
    .eq("status", "active");  // idempotency: only revoke still-active ones

  if (updateErr) {
    console.error("permits update failed", updateErr);
    return errorResponse(500, "server_error", "Failed to revoke permits");
  }

  // 5. Emit a `revoked` event on the SSE stream for each permit.
  //    Fire-and-forget — don't block the response on event delivery.
  for (const permitId of permitIds) {
    emitDecisionEvent(orgId, {
      type: "revoked",
      permit_id: permitId,
      actor_id: effectiveRevokerId,
      payload: {
        reason,
        workflow_id,
        run_id,
        revoked_by: effectiveRevokerId,
      },
    }).catch((err) => console.error("SSE emit failed", permitId, err));
  }

  // 6. Audit log entry
  await supabaseAdmin.from("audit_events").insert({
    org_id: orgId,
    event_type: "permits.bulk_revoked",
    actor_id: effectiveRevokerId,
    api_key_id: keyId,
    payload: {
      workflow_id,
      run_id,
      revoked_count: permitIds.length,
      reason,
      permit_ids: permitIds,
    },
  }).then(({ error }) => {
    if (error) console.error("audit log insert failed", error);
  });

  return successResponse(
    { revoked_count: permitIds.length, workflow_id, run_id },
    req,
  );
});
```

---

## Error responses

| Status | `reason` code | Condition |
|--------|---------------|-----------|
| 400 | `bad_request` | Missing/invalid `workflow_id`, `run_id` (not a UUID), `reason` empty or >1024 chars |
| 401 | `invalid_api_key` | Missing, expired, or revoked API key |
| 403 | `forbidden` | Key lacks `temporal` scope (if scope gates are added) |
| 429 | `rate_limited` | Per-key limit exceeded (same bucket as `/v1-evaluate`) |
| 500 | `server_error` | DB error during select or update |

**HTTP 404 is not returned** even when `revoked_count: 0`. A missing
run_id is indistinguishable from "all permits expired" from the server's
perspective, and the caller doesn't need to distinguish them.

---

## Idempotency

The `UPDATE ... WHERE status = 'active'` guard makes the operation
naturally idempotent: a second call for the same `run_id` finds no
active permits and returns `revoked_count: 0`. No explicit idempotency
key or deduplication table is needed.

If the same run sends multiple signals (race condition in the Temporal
workflow), only the first call produces non-zero `revoked_count`. This
is the correct behavior — the SDK retries on `network` errors but does
not retry on 200 responses, so double-revoke is safe.

---

## SSE event shape (`revoked`)

Each revoked permit emits one `revoked` `DecisionEvent` on
`GET /v2/decisions:subscribe`. Shape per
`contract/schemas/v2/decision-event.schema.json`:

```json
{
  "id": "<monotonic-event-id>",
  "type": "revoked",
  "org_id": "<org-id>",
  "emitted_at": "2026-04-29T12:00:00Z",
  "permit_id": "<permit-id>",
  "actor_id": "deploy-bot",
  "payload": {
    "reason": "Workflow completed — permits no longer needed",
    "workflow_id": "deploy-prod-2026-04-29",
    "run_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "revoked_by": "deploy-bot"
  }
}
```

Emit one event per revoked permit (not one per bulk call) so SSE
subscribers can react at the individual-permit level.

---

## Rate limiting

Count the bulk-revoke call as **one** rate-limit decrement against the
org's per-key budget (same as `/v1-evaluate`). Do not multiply by
`revoked_count` — bulk callers should not be penalized for revoking
many permits at once.

---

## `verifyPermit` invalidation

After revocation, any in-flight `POST /v1-verify-permit` call against a
revoked permit must return `decision: "DENY"` with `reason: "revoked_by_workflow"`.

The existing permit-validity check in `v1-verify-permit` already reads
`permits.status`. No additional work is needed there as long as the
status update in step 4 above is committed before the verify call
completes. (PostgreSQL's default `READ COMMITTED` isolation level
guarantees this.)

---

## Testing checklist

- [ ] `revoked_count: 0` when no active permits exist for `run_id`.
- [ ] Correct count when N permits exist and all are active.
- [ ] Second call for same `run_id` returns `revoked_count: 0` (idempotency).
- [ ] Concurrent revoke + consume race: whichever wins, no 500; the loser sees `revoked_count: 0` or stale `status`.
- [ ] `verifyPermit` returns `DENY` after revocation.
- [ ] SSE stream emits `revoked` event for each permit; count matches `revoked_count`.
- [ ] `revoker_id` optional: omitting defaults to `workflow_id` in audit log.
- [ ] `run_id` belonging to a different org returns `revoked_count: 0` (no cross-org leak).
- [ ] 400 on missing `workflow_id`, missing `reason`, malformed `run_id`.
- [ ] Rate-limit header triple present on every 200 response.
