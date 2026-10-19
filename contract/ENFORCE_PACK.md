# Enforce Pack — spec (DRAFT)

Status: **draft, not yet implemented.** This document defines the
canonical SDK surface that satisfies the AtlaSent SDK Strategy Lock
(2026-04-29). No code yet — review and revise before implementation
starts.

## Purpose

A net-new SDK package whose only job is to make every authorization
decision **non-bypassable** at the SDK layer. Wraps the existing v1
client (`atlasent` 1.4.x / `@atlasent/sdk` 1.4.x) and forces every
execution path through `verify-permit` before the wrapped action is
called. Fails closed on any error condition.

It is the runtime contract referenced by the lock as "Alpha Pack."
The v1 packages remain in place; over time, callers migrate from
direct v1 client use to the Enforce Pack. New v2 features (preview
pack) layer on top of Enforce, never around it.

## Naming

- TypeScript: `@atlasent/enforce` (npm)
- Python: `atlasent-enforce` (PyPI)
- Go (post-GA): `github.com/atlasent-systems-inc/atlasent-sdk/go/enforce`

Open: confirm names. The previous `v2-alpha` / `v2-preview` naming is
left alone (those packages remain as primitives + wire types, not the
enforcement contract).

## Surface (TypeScript shown; Python mirrors)

```ts
import { Enforce } from "@atlasent/enforce";
import { AtlasentClient } from "@atlasent/sdk"; // v1

const enforce = new Enforce({
  client: new AtlasentClient({ apiKey, baseUrl }),
  // failClosed is locked to true; the option exists only to be
  // explicit at the call site. Construction throws if set to false.
  failClosed: true,
  // Required: the org/actor/action context the wrapper authorizes against.
  bindings: { orgId, actorId, actionType },
});

// Single execution — the only public way to run a gated action.
await enforce.run({
  request: { /* CDO inputs */ },
  execute: async (permit) => {
    // Only invoked if verifyPermit() succeeded against the issued
    // permit. `permit` is the verified permit token; the closure
    // cannot side-step verifyPermit() because the wrapper never
    // exposes evaluate() without it.
    return await doTheThing(permit);
  },
});
```

There is **no** `evaluate()`-only entry point on the Enforce surface.
To evaluate without executing, callers stay on the v1 client; the
Enforce Pack is specifically for gated execution.

## Invariants (CI-enforced)

1. **Every `Enforce.run()` call issues `evaluate → verifyPermit → execute` in that order.** No public method skips verifyPermit.
2. **Fail-closed is non-toggleable.** The constructor rejects `failClosed: false`. The internal default is also true; the option is keyword-only to keep call sites readable.
3. **`execute` callback receives only the verified permit, never raw evaluation results.** Prevents callers from acting on an `allow` decision that hasn't yet been bound to a permit.
4. **Network errors during `verifyPermit` deny.** 4xx, 5xx, timeout, DNS, TLS — all map to a fail-closed deny with `reason_code: "verify_unavailable"`.
5. **Permit-binding mismatch denies.** If the permit's `org_id` / `actor_id` / `action_type` differs from the bindings configured on the Enforce instance, deny with `reason_code: "binding_mismatch"`.
6. **Expired or already-consumed permits deny.** No retry, no fallback to re-evaluate — caller must invoke `Enforce.run()` again to get a fresh permit.
7. **No second execution path.** A repo-level lint (CI job `enforce-no-bypass`) greps the Enforce package source for: direct imports of v1 `evaluate()` outside the wrapper, `eval`/`Function`/dynamic require, and any HTTP call that doesn't go through the wrapper's verify step. Any match fails CI.

## Failure-mode table

| Scenario | Decision | reason_code | Side effect |
|---|---|---|---|
| `evaluate` returns `allow` + valid permit | `allow` | n/a | execute runs |
| `evaluate` returns `deny` / `hold` / `escalate` | passthrough | from server | execute does not run |
| `evaluate` 4xx | deny | `evaluate_client_error` | execute does not run |
| `evaluate` 5xx / timeout | deny | `evaluate_unavailable` | execute does not run |
| `verifyPermit` 4xx | deny | `verify_client_error` | execute does not run |
| `verifyPermit` 5xx / timeout | deny | `verify_unavailable` | execute does not run |
| Permit binding mismatch | deny | `binding_mismatch` | execute does not run |
| Permit expired | deny | `permit_expired` | execute does not run |
| Permit already consumed | deny | `permit_consumed` | execute does not run |
| Permit revoked (D3 endpoint) | deny | `permit_revoked` | execute does not run |
| Permit not found (lookup miss) | deny | `permit_not_found` | execute does not run |
| `execute` throws | propagated | n/a | permit recorded as consumed; caller's exception preserved |

## Test obligations

Every public method has a paired "bypass attempt" test:

- `Enforce.run` cannot be invoked with a stub that skips verifyPermit (the wrapper itself orchestrates; callers can't inject the order).
- Constructing with `failClosed: false` throws.
- Mock-injecting a v1 client whose `verifyPermit` is replaced with a no-op causes `Enforce.run` to throw at construction time (the wrapper runtime-checks the client's method identity).
- The `enforce-no-bypass` lint catches any new file that imports v1 `evaluate()` directly.

Coverage floor: 100% on the Enforce package (lower than other packages = unacceptable for an enforcement primitive).

## SIM gate

SIM-01..SIM-10 (see `contract/SIM_SCENARIOS.md`) must pass on every
Enforce release. CI fails if any scenario regresses or is skipped.

## Integration gate

Before the Preview lane unparks: at least one real customer integration
uses Enforce in production for ten consecutive business days with
zero fail-closed-deny noise above baseline. "Real" excludes
examples-repo demos and dogfooding inside this repo's own tests.

## Migration items (post-GA)

Once Enforce is GA-validated (SIM-01..SIM-10 pass + ≥1 real
integration), the following v1 surfaces should migrate to call
`Enforce.run()` instead of `protect()` directly so framework
integrations also get the non-bypassable wrapper guarantee:

- **Hono middleware** (`typescript/src/hono.ts`) — see the dedicated
  section below.
- **Other framework wrappers** as they ship: same pattern. Any new
  framework integration MUST be built on `Enforce.run()` from the
  start, never on `protect()` directly. Reviewers should reject PRs
  that wire a new framework on top of v1 `protect()`.

These are intentionally post-GA: shipping Enforce + the SIM gate
first gives us a stable target to migrate against.

---

## Hono middleware migration (`@atlasent/sdk/hono`)

### Current state

`atlaSentGuard` in `typescript/src/hono.ts` (line 113) calls
`protect(request)` directly:

```ts
const permit: Permit = await protect(request);
c.set(contextKey, permit);
await next();
```

`protect()` wraps the v1 `evaluate` call but does **not** enforce the
full `evaluate → verifyPermit → execute` chain as a non-bypassable
invariant. The guard therefore bypasses the Enforce Pack contract.

### Why this matters

The Hono middleware is the most common entry point for server-side
route protection. If it doesn't go through `Enforce.run()`, every
Hono-guarded route has a parallel execution path that the
`enforce-no-bypass` lint cannot see — the v1 `protect()` function is
not in `@atlasent/enforce`'s source tree, so the lint never runs on
it. The migration closes this gap.

### Migration target (post Enforce GA)

The guard is rebuilt so the route handler is the `execute` callback
passed to `Enforce.run()`. The middleware receives a pre-constructed
`Enforce` instance (dependency-injected, not constructed per-request)
so that `bindings` are validated at app startup, not per call.

**Proposed API (TypeScript)**

```ts
import { Enforce } from "@atlasent/enforce";
import { atlaSentGuard, atlaSentErrorHandler } from "@atlasent/sdk/hono";

const enforce = new Enforce({
  client,
  bindings: { orgId, actorId: (c) => c.get("userId"), actionType: "deploy" },
  failClosed: true,
});

app.post(
  "/deploy",
  atlaSentGuard({ enforce }),           // enforce instance injected
  (c) => {
    const permit = c.get("atlasent");   // VerifiedPermit (was: Permit)
    return c.json({ ok: true, permitId: permit.token });
  },
);

app.onError(atlaSentErrorHandler());
```

Key changes from the current surface:

| | Current (`protect`-based) | Migrated (`Enforce.run`-based) |
|---|---|---|
| Config | `action`, `agent`, `context` per-route | `enforce` instance (owns `bindings`); `request` builder per-route |
| Context value (`c.get("atlasent")`) | `Permit` (v1) | `VerifiedPermit` (from Enforce) |
| Guard calls | `protect(request)` directly | `enforce.run({ request, execute: next })` |
| Bypass possible? | Yes — `protect` skips verifyPermit path | No — `Enforce.run` enforces the chain |

### Error-handler changes

`atlaSentErrorHandler` continues to map `AtlaSentDeniedError` and
`AtlaSentError` to HTTP responses. After migration it also maps the
new `ReasonCode` values surfaced by `Enforce.run()`:

| reason_code | Default HTTP status | Meaning |
|---|---|---|
| `verify_unavailable` | 503 | `verifyPermit` 5xx / timeout |
| `verify_client_error` | 502 | `verifyPermit` 4xx |
| `verify_latency_breach` | 503 | verify did not complete within `latencyBudgetMs` |
| `binding_mismatch` | 403 | permit org/actor/action doesn't match Enforce bindings |
| `permit_expired` | 403 | permit TTL passed before verify completed |
| `permit_consumed` | 409 | permit was already used (replay attempt) |
| `permit_revoked` | 403 | permit explicitly revoked via `POST /v1-permits/{id}/revoke` (D3) |
| `permit_not_found` | 404 | permit id not recognized server-side |
| `permit_tampered` | 403 | permit signature invalid |

The `permit_*` reasonCodes are aligned by name with the v1 SDK's
`PermitOutcome` discriminator (atlasent-sdk PR #132 / #133), so an
adapter that surfaces a v1 `AtlaSentDeniedError` to Enforce can
forward `err.outcome` directly as the `reasonCode` without remapping.
The `PermitOutcomeReasonCode` exported from `@atlasent/enforce`
narrows `ReasonCode` to exactly that subset.

These codes are additive — existing `deny` / `hold` / `escalate`
mappings remain unchanged.

### What is blocked until Enforce GA

- Rewriting `atlaSentGuard` on `Enforce.run()` is **blocked** until
  Enforce GA (SIM-01..SIM-10 pass + ≥1 real integration). Migrating
  before a stable `Enforce` target would mean rewriting the middleware
  twice.
- The existing `protect()`-based guard ships with v1 and is not
  deprecated until the migrated guard is available and the
  `@atlasent/sdk/hono` subpath is updated to re-export from
  `@atlasent/enforce/hono`.

### Tracking

This migration is tracked as a follow-on to the Enforce GA milestone.
Do not open a PR that wires `atlaSentGuard` onto `Enforce.run()` until
both of these are true:
1. `@atlasent/enforce` passes SIM-01..SIM-10 in CI.
2. The integration gate (≥1 real integration, 10 business days) is met.

Open a dedicated PR against `main` when ready; do not stack it on the
Enforce skeleton PRs.

---

## Out of scope (intentionally)

- Streaming / SSE / batch — those are Preview-pack features that layer on top of Enforce later.
- Retry policy on `evaluate` 5xx — Enforce denies; the v1 client's existing retry is bypassed for `verifyPermit` (one shot, fail-closed).
- Pluggable transport / custom HTTP — Enforce uses the v1 client's transport. No new transport surface.

## Open questions

- Naming: `@atlasent/enforce` or `@atlasent/gate` or `@atlasent/protect`? The v1 package already exposes a `protect()` function, so `protect` would collide. `enforce` is unambiguous; happy to revise.
- Multi-action `Enforce.runAll([...])` for batching? Defer to Preview pack (gated behind SIM-01..SIM-10 and the integration gate); a non-bypassable batch wrapper is more complex than v1 batch and shouldn't be in the first cut.
- Permit-cache: should Enforce cache permits across calls inside a single process for performance? Default no (simplicity, easier to reason about fail-closed). If we add it later, cache is per-binding-tuple and never crosses orgs.
- Error-on-server-down: hard deny vs. hard error? Today's spec says deny with reason_code; alternative is to throw a typed exception so callers can distinguish "server says deny" from "can't reach server." The lock says fail-closed, so deny is correct — keep it.
- Hono `bindings` per-request actor resolution: the migration sketch shows `actorId: (c) => c.get("userId")` as a function resolver. Should `Enforce` accept resolver functions for binding fields, or should the guard middleware resolve them and construct a per-request `Enforce`? Per-request construction is simpler but adds overhead. Preferred: a lightweight resolver protocol on `Enforce` so the instance is created once at startup.
