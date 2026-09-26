# atlasent-sdk — V2 Rollout (historical filename)

> **Reframing normalization header (2026-05-18, second-pass).** This
> document is preserved per the "do not rewrite history" doctrine
> (the internal `VERSIONING_DOCTRINE.md`
> Doctrine 4). Under the 2026-05-18 normalization pass, the
> platform-generation `v2 / v3` framing has been retired: there is no
> "v2 product" and no "v3 product." There is only **AtlaSent v1** (the
> stable public contract) plus **Phase 1 / Phase 2 / Phase 3** of
> additive evolution on top of `v1`.
>
> The substantive SDK work below — batch evaluate, streaming evaluate,
> GraphQL client, framework guards, behavior-conditioning helper —
> ships additively on the `v1` contract and is sequenced as **Phase 1
> — Stabilization & Pilot Readiness** (with the offline-replay client
> belonging to Phase 3). The "V2", "Wave B", `v2_*` tenant-flag
> identifiers, `@atlasent/sdk@2.x` SemVer references, and
> `@atlasent/behavior@1.0.0` references in this document are historical
> pre-reframing labels and **code-level identifiers** — per Doctrines 4
> and 5, the filename, decision IDs, package names, and per-package
> SemVer (which evolves independently of platform phases) are all
> preserved. New decisions use the **`PROD-D#`** namespace. See
> the internal `ROADMAP.md`
> for the current phase matrix and `ROADMAP.md` in this repo for the
> SDK slice.

**Status:** in progress · **Wave:** B (SDKs + MCP) · **Updated:** 2026-05-22

> **V1 GA — 2026-05-17.** V1 substrate frozen — the canonical foundation
> this V2 plan extends. The `/v1/*` wire surface, schema, audit chain,
> and Ed25519-signed export envelope are stable; V2 work in this plan is
> **additive** on V1 (no V1 wire/schema/audit-chain changes ship under V2).
> V2 implementation is unblocked pending umbrella
> the internal `V2_DECISIONS.md` sign-off.
> Canonical V1 reference: the internal runtime golden-path V1 guide (`golden-path-v1.md`).
> V1 GA closeout PRs: see the internal umbrella `ROADMAP.md` "V1 GA — what closed" section.

SDK cut of the internal umbrella v2 rollout. This repo is the **publish-gating fan-out point** — `atlasent-action`, `langchain-llamaindex-integration`, `atlasent-mcp-server`, `atlasent-examples`, `gxp-starter`, and three downstream apps all pin against the 2.x tag that ships from here.

## Position

The 1.x SDKs target two endpoints (`/v1-evaluate`, `/v1-verify-permit`). v2 expands the wire surface to the new additive endpoints (`/v1/evaluate/batch`, `/v1/evaluate/stream`, `/v1/graphql`) and ships the `@atlasent/behavior` helper that every behavior-conditioning consumer references. v1.x methods stay available throughout — v2 is additive, not breaking.

## v2 deliverables (Wave B)

| ID | Item | Status |
|---|---|---|
| B.SDK1 | TS — `evaluateMany(transport, req)` over `/v1/evaluate/batch`; `FeatureNotEnabledError` on `v2_batch=false` (404) | ✅ done — `typescript/src/v2.ts` |
| B.SDK2 | TS — `authorizeStream(transport, req, handlers)` SSE streaming over `/v1/evaluate/stream`; `onDecision`/`onError` callbacks; terminal `StreamComplete` | ✅ done — `typescript/src/v2.ts` |
| B.SDK3 | TS — `graphql(transport, req)` over `/v1/graphql`; admin-key bearer auth; resolver errors on `response.errors`, not thrown | ✅ done — `typescript/src/v2.ts` |
| B.SDK4 | Python — `client.authorize_many([...])` + `authorize_many_async` | pending |
| B.SDK5 | Python — `client.authorize_stream(...)` (sync iterator + `_async` async iterator); SSE parser | pending |
| B.SDK6 | Python — `client.graphql(...)` mirror | pending |
| B.SDK7 | Go — `client.EvaluateMany(ctx, reqs)` + `client.AuthorizeStream(ctx, req)` channel-based stream | pending |
| B.SDK8 | `@atlasent/types` 2.x — `EvaluateBatchResponse`, `EvaluateBatchItem`, `EvaluateManyRequest`, `StreamDecisionFrame`, `StreamComplete`, `GraphQLRequest`, `GraphQLResponse` in `src/v2.ts`; `BvsSnapshot`, `BehaviorCategory`, `StateSummary`, `CategoryAggregate` in `typescript/packages/behavior/src/types.ts` | ✅ done — ship-ready; publish gated per governance |
| B.SDK9 | **`@atlasent/behavior` helper** — `getStateSummary`, `getCategoryAggregate`, `attachToEvaluate`; reads aggregates-only from `behavior-insights` `pattern_entries`; redacted projection only (no raw text). Exported via `@atlasent/sdk/behavior` and `typescript/packages/behavior/` standalone. | ✅ done — `typescript/packages/behavior/src/` + `./behavior` export in main package |
| B.SDK10 | `AtlaSentEscalateError` — distinct from `AtlaSentDeniedError`; raised on `decision: "escalate"` so middleware can route to human review; `userId` field for HITL correlation | ✅ done — `typescript/src/errors.ts` |
| B.SDK11 | Publish — npm `@atlasent/sdk@2.x` + `@atlasent/behavior@1.0.0`; publish held per governance until runtime stabilization + deployment topology reconciliation complete | ✅ done — `@atlasent/sdk@2.5.0` in registry; **publish of 2.x gated** per governance constraint until staging verification completes |
| B.SDK12 | Proof-system offline-replay client — `client.replay(decisionId)` verifies decision via signed bundle without backend round-trip; gated by `v2_proof_system` | pending — v3 candidate, sketched in 2.1 minor |

## Tenant-flag matrix

| Flag | Module |
|---|---|
| `v2_batch` | B.SDK1, B.SDK4, B.SDK7 |
| `v2_streaming` | B.SDK2, B.SDK5, B.SDK7 (stream half) |
| `v2_graphql` | B.SDK3, B.SDK6 |
| `v2_behavior_conditioning` | B.SDK9, B.SDK10 |
| `v2_proof_system` | B.SDK12 (when promoted) |

## Behavior Conditioning Layer (B.SDK9)

`@atlasent/behavior` is fully implemented in `typescript/packages/behavior/src/`. The main `@atlasent/sdk` package also exposes a `./behavior` export entry pointing to `src/behavior.ts`. Downstream consumers (`atlasent-mcp-server` C.MCP1, `langchain-llamaindex-integration` C.LL6, `gxp-starter` HIPAA pack, `atlasent-examples` flow 07) can import from either path.

Published surface:
- `getStateSummary(userId, clientOpts, opts?)` — returns the redacted `StateSummary` projection
- `getCategoryAggregate(userId, category, clientOpts, opts?)` — per-category counts for the four HIPAA behavior categories
- `attachToEvaluate(userId, clientOpts)` — stamps `behavior_context` onto an evaluate request's metadata field

Aggregates-only contract: the helper never reads raw event text. The wire shape is frozen by `behavior-insights` BI4.

## Sequencing

1. B.SDK8 (`@atlasent/types` 2.x) — ✅ done; types ship in `src/v2.ts` + `packages/behavior/src/types.ts`
2. B.SDK1–B.SDK3 (TS batch/stream/graphql) — ✅ done; in `src/v2.ts`
3. B.SDK9 (`@atlasent/behavior`) — ✅ done
4. B.SDK10 (`AtlaSentEscalateError`) — ✅ done; in `src/errors.ts`
5. B.SDK11 (publish) — ✅ done at 2.5.0; **end-to-end gating behind staging confirmation** per governance
6. B.SDK4–B.SDK7 (Python/Go) — pending; not blocking TS consumers
7. B.SDK12 (proof-system offline replay) — v3 candidate

## Cross-repo dependencies

- **atlasent-api**: `/v1/evaluate/{batch,stream}`, `/v1/graphql`, frozen `EvaluateStreamEvent` schema (Wave A)
- **atlasent-control-plane**: tenant-flag service; SDK reads flags via small `flagsClient` for client-side fallback behavior on `v2_*=false`
- **behavior-insights**: BI2 (`pattern_entries` read API), BI3 (sensitive-category aggregates), BI4 (frozen `BvsSnapshot` wire shape)
- **openaispec**: GraphQL SDL mirror — open question whether to publish as a separate `@atlasent/graphql-schema` package (per `openaispec/V2_ROLLOUT.md`)
- **atlasent-action**, **langchain-llamaindex-integration**, **atlasent-mcp-server**, **atlasent-examples**, **gxp-starter**: all unblock on B.SDK11 publish

## Out of scope for Wave B

- Mutating GraphQL — read-only in Wave A; mutations stay on REST (per `atlasent-api/V2_ROLLOUT.md`)
- TS package split (`@atlasent/sdk-v2` side-by-side) — current direction is in-place major bump (umbrella open question)
- Temporal Activity wrappers — `v2_temporal` flag is parked; v3 candidate
- Self-hosted-mode SDK helpers — `v2_self_hosted` flag is parked; v3 candidate

## Open questions

- In-place 2.x bump vs side-by-side `@atlasent/sdk-v2` (umbrella open question — SDK owns the call)
- `@atlasent/behavior` package layout: standalone, or peer-exported from `@atlasent/sdk`? (both currently ship)
- Stream auth: bearer query param vs cookie vs header (umbrella open question, blocks B.SDK2/B.SDK5)
- Go module path: `v2` semver-major suffix (`github.com/.../atlasent-sdk/go/v2`) or unsuffixed pre-1.0 major?
- Should `evaluateMany` accept a generator/iterable for streaming-large-batch use cases, or only an array?

## Cross-repo links

- Umbrella plan: the internal umbrella `V2_ROLLOUT.md`
- API plan: the internal API-side `V2_ROLLOUT.md`
- Control-plane plan: the internal control-plane `V2_ROLLOUT.md`
- Behavior-insights plan: this branch, sibling repo
- Behavior layer spec: the internal `V2_BEHAVIOR_CONDITIONING_LAYER.md`
