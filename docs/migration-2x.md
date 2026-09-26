# Migrating from `@atlasent/sdk@1.x` to `2.x`

This guide covers all breaking changes, new features, and recommended
migration steps for consumers upgrading from `@atlasent/sdk@1.x` to `2.x`.

---

## Overview

`@atlasent/sdk@2.x` ships three categories of change:

1. **Wire-format reconciliation** (breaking) — the request/response body
   fields changed to match the canonical `atlasent-api` wire contract.
2. **New capability-layer APIs** (additive) — batch evaluation, SSE streaming,
   and a read-only GraphQL endpoint (V2 Wave A).
3. **New error class** (additive, soft-breaking) — `AtlaSentEscalateError`
   distinct from `AtlaSentDeniedError`.

All 1.x public method signatures are preserved; compat shims translate the
old wire shapes transparently. The shims emit `console.warn` on legacy
field usage and are removed in `@atlasent/sdk@3`.

---

## 1. Install

```bash
npm install @atlasent/sdk@^2.0.0
# or
bun add @atlasent/sdk@^2.0.0
```

If you use `@atlasent/behavior-preview`, also install the stable replacement:

```bash
npm install @atlasent/behavior@^1.0.0
```

---

## 2. Breaking changes

### 2.1 Wire request fields renamed

The 2.x SDK sends the canonical field names the AtlaSent API now requires.
You only need to act if you were constructing raw evaluate requests — the
public `AtlaSentClient` methods still accept the 1.x field names and translate
them internally (with a `console.warn`).

| 1.x field | 2.x field | Notes |
|-----------|-----------|-------|
| `agent` | `actor_id` (snake_case — matches the wire) | Both accepted in 2.x via compat shim; there is no `actorId` camelCase variant on `evaluate()` |
| `action` | `action_type` (snake_case — matches the wire) | Both accepted in 2.x via compat shim; there is no `actionType` camelCase variant on `evaluate()` |
| `api_key` in body | Removed | Key now sent exclusively via `Authorization: Bearer` header |

```ts
// 1.x — still works in 2.x (compat shim, console.warn)
const result = await client.evaluate({
  agent: "deploy-bot",
  action: "production.deploy",
  context,
});

// 2.x — recommended (canonical field names are snake_case, not camelCase)
const result = await client.evaluate({
  actor_id: "deploy-bot",
  action_type: "production.deploy",
  context,
});
```

### 2.2 Response field changes

| 1.x field | 2.x field | Notes |
|-----------|-----------|-------|
| `permitted: boolean` | Removed from canonical shape | Use `decision_canonical === "allow"` |
| `decision_id` | `evaluationId` (camelCase) or `permit.permitId` | |
| `decision: 'ALLOW' \| 'DENY'` | **Deprecated** — use `decision_canonical` | 2-value uppercase field collapses `hold`/`escalate` into `'DENY'`; removal in v3 |

```ts
// 1.x
if (!result.permitted) throw new Error(result.reason);

// 2.x — recommended
if (result.decision_canonical !== "allow") {
  // EvaluateResponse has no `.denial` object — use `.reason` (human-readable)
  // and/or `.deny_code` (machine-readable, non-null only on deny).
  throw new Error(result.reason || result.deny_code || "Denied");
}
```

### 2.3 `verifyPermit` no longer sends `context`

The deployed verify handler does not consult `context`. Passing it is
still silently accepted (not an error) but the field is stripped from
the wire body. No action required unless you were depending on
`context` being echoed back in a verify response (it wasn't).

### 2.4 `AtlaSentEscalateError` is now a distinct class

In 1.x, an `escalate` decision arrived as `AtlaSentDeniedError` with
`decision: "escalate"`. In 2.x it is thrown as `AtlaSentEscalateError`.

If you were catching `AtlaSentDeniedError` and inspecting `.decision`,
update your catch block:

```ts
import {
  protect,
  AtlaSentDeniedError,
  AtlaSentEscalateError,
  AtlaSentError,
} from "@atlasent/sdk";

try {
  // `protect()` is a standalone function (not a method on AtlaSentClient),
  // and takes { agent, action, context } — not { actorId, actionType }.
  const permit = await protect({ agent, action, context });
  await runAction(permit);
} catch (e) {
  if (e instanceof AtlaSentEscalateError) {
    // Escalation: route to human review queue, do NOT proceed
    await humanReviewQueue.submit({
      requestId: e.requestId,
      userId: e.userId,
      action,
    });
  } else if (e instanceof AtlaSentDeniedError) {
    // Hard denial — log and surface to the caller
    logger.warn("AtlaSent denied", {
      reason:       e.reason,
      evaluationId: e.evaluationId,
      outcome:      e.outcome,   // permit_consumed | permit_expired | ...
    });
    throw new PermissionDeniedError(e.reason);
  } else if (e instanceof AtlaSentError) {
    // Transport / auth / rate-limit error
    throw e;
  }
}
```

`instanceof AtlaSentError` still catches all three types — the error
hierarchy is additive.

---

## 3. What's new in 2.x

### 3.1 `evaluateMany` — batch evaluation

Evaluate up to 100 items in one round-trip. Requires the `v2_batch`
tenant feature flag; throws `FeatureNotEnabledError` when the flag
is off.

```ts
import { evaluateMany, type V2Transport } from "@atlasent/sdk/v2";

const transport: V2Transport = {
  baseUrl: "https://api.atlasent.io",
  apiKey: process.env.ATLASENT_API_KEY!,
};

const result = await evaluateMany(transport, {
  items: actions.map((a) => ({
    action_type: a.type,
    actor_id:    a.agentId,
    context:     a.context,
  })),
});

for (const item of result.items) {
  if (item.decision === "allow") {
    await runAction(actions[item.index]);
  } else if (item.errorCode) {
    logger.error("batch item failed", item);
  }
}
```

### 3.2 `authorizeStream` — SSE streaming authorization

Stream decisions as they arrive via Server-Sent Events. Per-item
failures arrive as `error` frames without tearing down the stream.
Requires the `v2_streaming` tenant feature flag.

```ts
import { authorizeStream } from "@atlasent/sdk/v2";

const complete = await authorizeStream(
  transport,
  { items },
  {
    onDecision: ({ index, decision, permitToken }) => {
      if (decision === "allow") dispatch(actions[index], permitToken);
    },
    onError: ({ index, errorCode, message }) => {
      logger.error(`item ${index} failed: ${errorCode} — ${message}`);
    },
  },
);
console.log(`done: ${complete.count} evaluated, partial=${complete.partial}`);
```

### 3.3 `graphql` — read-only governance queries

Query the AtlaSent read-only GraphQL API (Wave A schema: recent
evaluations, active policy bundle). Requires the `v2_graphql`
tenant feature flag.

```ts
import { graphql } from "@atlasent/sdk/v2";

const { data, errors } = await graphql<{ recentEvaluations: unknown[] }>(
  transport,
  {
    query: `{
      recentEvaluations(limit: 20) {
        decisionId
        decision
        actorId
        actionType
        decidedAt
      }
    }`,
  },
);
if (errors?.length) console.warn("GraphQL errors", errors);
if (data) renderDashboard(data.recentEvaluations);
```

### 3.4 Feature-flag gating with `FeatureNotEnabledError`

All three V2 endpoints are closed-by-default per tenant. Catch
`FeatureNotEnabledError` to implement a deterministic v1 fallback:

```ts
import { evaluateMany, FeatureNotEnabledError } from "@atlasent/sdk/v2";

try {
  return await evaluateMany(transport, { items });
} catch (e) {
  if (e instanceof FeatureNotEnabledError && e.feature === "batch") {
    // Fall back to sequential per-item v1 calls
    return await Promise.all(items.map((item) => client.evaluate(item)));
  }
  throw e;
}
```

---

## 4. `@atlasent/behavior` — new package for BVS integration

`@atlasent/behavior@1.0.0` graduates from `@atlasent/behavior-preview`
and is now stable. It provides three functions for integrating the
Behavior Verification System (BVS) with the AtlaSent evaluate flow.

### Install

```bash
npm install @atlasent/behavior@^1.0.0
```

### Usage

```ts
import { getStateSummary, getCategoryAggregate, attachToEvaluate } from "@atlasent/behavior";
import { AtlaSentClient } from "@atlasent/sdk";

const client = new AtlaSentClient({ apiKey: process.env.ATLASENT_API_KEY! });

const behaviorClientOpts = {
  baseUrl: process.env.BEHAVIOR_INSIGHTS_URL!,
  apiKey:  process.env.BEHAVIOR_API_KEY!,
};

// Option A: enriched evaluate (recommended for most callers)
const behaviorContext = await attachToEvaluate(userId, behaviorClientOpts);
const result = await client.evaluate({
  actor_id:    userId,
  action_type: "production.deploy",
  context:     { ...appContext, ...behaviorContext },
});

// Option B: manual state summary
const summary = await getStateSummary(userId, behaviorClientOpts);
if (summary && summary.event_count > 0) {
  // use summary.category_counts, summary.window_start, etc.
}

// Option C: single-category aggregate
const agg = await getCategoryAggregate(userId, "behavior.financial", behaviorClientOpts);
if (agg.confidence_low) logger.warn("low-confidence behavior signal");
```

### Migrate from `@atlasent/behavior-preview`

`@atlasent/behavior-preview` is deprecated. All three exported functions
have the same signatures:

```diff
-import { getStateSummary, getCategoryAggregate, attachToEvaluate } from "@atlasent/behavior-preview";
+import { getStateSummary, getCategoryAggregate, attachToEvaluate } from "@atlasent/behavior";
```

---

## 5. Deprecation timeline

| Item | Deprecated in | Removed in |
|------|--------------|------------|
| `evaluate({ agent, action })` legacy field names | 2.0.0 | 3.0.0 |
| `decision: 'ALLOW' \| 'DENY'` (2-value uppercase) | 2.0.0 | 3.0.0 |
| `permitted: boolean` on `EvaluateResponse` | 2.0.0 | 3.0.0 |
| `client.revokePermit()` (token-in-body) | 2.2.0 | 3.0.0 |
| `client.verifyPermit()` (token-in-body) | 2.2.0 | 3.0.0 |
| `DEPLOYMENT_PRODUCTION_ACTION` constant | 2.3.0 | next minor |
| `@atlasent/behavior-preview` | 2.0.0 / behavior@1.0.0 | future |

---

## 6. Full type reference

Import types from `@atlasent/sdk` for all client-side work:

```ts
import type {
  // Core decision types
  EvaluateResponse,
  DecisionCanonical,       // 'allow' | 'deny' | 'hold' | 'escalate'
  PermitRecord,
  PermitStatus,

  // Error classes
  AtlaSentError,
  AtlaSentDeniedError,
  AtlaSentEscalateError,   // NEW in 2.x

  // V2 batch/stream types (from @atlasent/sdk/v2)
  EvaluateBatchResponse,
  EvaluateBatchItem,
  StreamDecisionFrame,
  StreamErrorFrame,
  StreamComplete,
  GraphQLRequest,
  GraphQLResponse,
  FeatureNotEnabledError,
} from "@atlasent/sdk";

import type {
  // Behavior types (from @atlasent/behavior)
  StateSummary,
  CategoryAggregate,
  BehaviorCategory,
  BvsSnapshot,
} from "@atlasent/behavior";
```

---

## 7. Getting help

- GitHub Issues: https://github.com/Atlasent/atlasent-sdk/issues
- CHANGELOG: [`typescript/CHANGELOG.md`](../typescript/CHANGELOG.md)
- BVS integration: [`typescript/packages/behavior/`](../typescript/packages/behavior/)
- V2 Wave A spec: [`contract/ENFORCE_PACK.md`](../contract/ENFORCE_PACK.md)
