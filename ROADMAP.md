# atlasent-sdk — Roadmap

> **Doctrine reference.** Per the internal `VERSIONING_DOCTRINE.md`
> (2026-05-18 normalization), the public AtlaSent contract is **v1**
> and stays `v1`. There is no "v2 platform" and no "v3 platform"; what
> previous drafts called `v2 / v3` is now sequenced as **Phase 1 /
> Phase 2 / Phase 3** of additive evolution on `v1`. **Per-language
> SDK package SemVer is independent of platform phases** per Doctrine 5:
> `@atlasent/sdk@2.x`, Python `atlasent` 2.x, and Go module `/v2`
> suffix are SDK ergonomics/typing majors — they are **not** "AtlaSent
> v2." Package names like `@atlasent/sdk-v2-preview`,
> `@atlasent/sdk-v2-alpha`, `atlasent_v2_alpha`, `atlasent_v2_preview`,
> the `@atlasent/temporal-preview` / `@atlasent/otel-preview` /
> `@atlasent/sentry-preview` / `@atlasent/behavior-preview` packages,
> and schema-version artifacts under `contract/vectors/v2/` and
> `contract/schemas/v2/` are **code-level identifiers** — preserved
> per Doctrines 3, 4, and 5.
>
> **Last updated:** 2026-05-27

Client SDKs: TypeScript (`@atlasent/sdk`), Python (`atlasent`). Nothing
ships to customers until these ship. SDK package SemVer evolves
independently of platform phases (see Doctrine 5 above).

## v1 contract status — May 2026

The SDKs implement the stable AtlaSent **v1** contract
(`evaluate → permit → verify → execute → audit`).

- **TypeScript `@atlasent/sdk` 2.11.0** on npm (tag: `typescript-v2.11.0`) — implements `v1`
  contract. Adds `client.auth`, `client.scim`, `client.evidenceBundles` sub-clients; TS retries with jitter; browser API key warning; `verifyEvidenceBundle` offline replay.
- **Python `atlasent` 2.11.0** on PyPI (tag: `python-v2.11.0`) — implements `v1` contract.
  Adds `atlasent.auth`, `atlasent.scim_client`, `atlasent.evidence_bundle`, `atlasent.replay`; unified `DecisionValue` type; `permit_expires_at` on `Permit`; `reasons: list[str]` on `EvaluateResult`.
- **Go SDK** — **reinstated** at `2.11.0`. `go/` module at `github.com/atlasent-systems-inc/atlasent-sdk/go/v2`. Includes `(*Client).Middleware()` net/http middleware, full `SCIMGroupsClient` (Create/Update/Delete), `put()` helper, `PermitContextKey`. 10 tests green.
- **Framework guard packages** (`@atlasent/langchain`,
  `@atlasent/llamaindex`, `@atlasent/cursor`) at 1.6.0 — tests green, README +
  LICENSE in place; **not yet published to npm** (blocked on org-wide
  Apache-2.0/MIT license decision).

Remaining to close out the current SDK-publishing arc:

- Publish framework guard packages to npm — unblocks agent-framework pilot
  scenarios; blocked on org-wide Apache-2.0/MIT license decision.

Known gaps tracked for later phases:

- Batch evaluate (blocked on atlasent-api `/v1/evaluate/batch` endpoint).
- Streaming evaluate (blocked on atlasent-api SSE endpoint).
- Sentry breadcrumbs on retry (Phase 2 stretch goal).

## Phase 1 — Stabilization & Pilot Readiness (SDK slice)

Additive on the `v1` contract. The SDKs ship the stable `v1` surface
plus the framework guards required for pilot deployments.

1. **TS SDK published** — `@atlasent/sdk` **2.11.0 on npm** (tag: `typescript-v2.11.0`).
   `@atlasent/types` lives in
   `atlasent-api/packages/types`; whether it ships as a separate npm
   package or folds into `@atlasent/sdk` is open.
2. **Python SDK published** — `atlasent` **2.11.0 on PyPI** (tag: `python-v2.11.0`).
   Sync + async clients, `protect()` / `authorize()` / `gate()` /
   `evaluate()` / `verify()`, `@atlasent_guard` + `@async_atlasent_guard`
   decorators, typed errors, `TTLCache`, audit-bundle verification.
3. **Go SDK** — **reinstated at 2.11.0**. Module path `github.com/atlasent-systems-inc/atlasent-sdk/go/v2`.
4. **`v1`-only API sweep** — done in the 1.x line.
5. **Offline verifier** — `@atlasent/verify` zero-dep Node CLI +
   library packaged. `verify_audit_bundle()` ships in both
   `atlasent` (Python) and TS SDK.
6. **SSO-aware types** — once `atlasent-api/v1-sso` ships, export
   `SsoConnection`, `SsoJitRule`, `SsoEvent` from `@atlasent/types`.

### Shipped (Phase 1, through 2026-05-11)

- **Python governance modules** — auditor access, policy certification,
  federation, financial governance.
- **TS governance enforcement helpers** — `GovernanceEnforcementLayer`,
  `APPROVAL_DENY_REASONS` taxonomy, governance-enforcement types;
  re-exported from `src/index.ts`.
- **6 TS regulatory governance gap modules** — cross-org permission,
  anomaly response, budget exceptions, regulatory escalation, financial
  governance, governance graph foundation.
- **Framework guard packages** — all three packages test-green, README
  + LICENSE added:
  - `@atlasent/langchain` — `withLangChainGuard(tools, client, opts)`.
    13 tests green.
  - `@atlasent/llamaindex` — `withLlamaIndexGuard(tools, client, opts)`.
    13 tests green.
  - `@atlasent/cursor` — `withCursorGuard(tools, client, opts)`. 13
    tests green.
- SCIM groups endpoint types mirroring atlasent-api.
- Typed decision/error/outcome models with `body.error` primary surface.
- Sandbox diff, delegation propagation, heterogeneous quorum types.

## Phase 2 — Enterprise Hardening & Runtime Expansion (SDK slice)

Additive on `v1`. Brings the SDKs to enterprise-procurement readiness
on top of the stable contract.

- ✅ **Retries with jitter** — `authorize()` / `protect()` retry transient 429 (`Retry-After` honoured as backoff floor) and 5xx. Full jitter, `maxAttempts: 3`, cap 10 s. Shipped in 2.11.0.
- ✅ **Unified decision type** — `DecisionValue = Literal["allow","deny","hold","escalate"]` exported from Python `atlasent` (mirrors TS `Decision`). `Permit.permit_expires_at` added (mirrors TS `permitExpiresAt`). `EvaluateResult.reasons: list[str]` added (mirrors TS `reasons: string[]`). Shipped in 2.11.0.
- ✅ **Browser guard** — one-time `console.warn` in `AtlaSentClient` constructor when real browser context detected. Shipped in 2.11.0.
- **Batch evaluate** — blocked on atlasent-api `/v1/evaluate/batch` endpoint.
- **Streaming evaluate** — blocked on atlasent-api SSE endpoint.
- **Sentry breadcrumbs** — stretch goal; deferred to after pilot feedback.

## Phase 3 — Execution Assurance & Operational Sovereignty (SDK slice)

Additive on `v1`. Raises the SDK surface to deterministic execution
assurance.

- ✅ **Go parity** — Go SDK reinstated at 2.11.0. `(*Client).Middleware()` net/http middleware, full `SCIMGroupsClient`. Module path suffix (`/v2`) follows Go's SemVer convention.
- ✅ **MCP server bump** — atlasent-mcp-server co-versioned to 2.11.0.
- ✅ **Offline replay client** — `verify_evidence_bundle()` (Python) and `verifyEvidenceBundle()` (TypeScript) verify an evidence bundle without a backend round-trip. 25 tests each. Shipped in 2.11.0.

## Publishing mechanics

- **npm**: `@atlasent/sdk`, `@atlasent/types`, `@atlasent/verify`,
  `@atlasent/cli`, `@atlasent/packs`, `@atlasent/langchain`,
  `@atlasent/llamaindex`, `@atlasent/cursor`, and the preview packages
  (`@atlasent/sdk-v2-preview`, `@atlasent/sdk-v2-alpha`,
  `@atlasent/temporal-preview`, `@atlasent/otel-preview`,
  `@atlasent/sentry-preview`, `@atlasent/behavior-preview`). Workflow:
  `.github/workflows/release.yml` on tag push. `NPM_TOKEN` secret
  required. Preview package names are published-identifier-stable per
  Doctrine 5.
- **PyPI**: `atlasent`, plus preview / experimental distributions
  (`atlasent_v2_alpha`, `atlasent_v2_preview`,
  `atlasent_temporal_preview`, `atlasent_otel_preview`,
  `atlasent_sentry_preview`). Workflow on tag. `PYPI_TOKEN` secret.
  Preview distribution names are published-identifier-stable per
  Doctrine 5.
- **Go proxy**: removed; will restore as a tagged module when re-added
  (module-path suffix per Go SemVer convention).
- **License blocker**: org-wide Apache-2.0/MIT decision pending counsel;
  framework guard packages (`@atlasent/langchain`, `@atlasent/llamaindex`,
  `@atlasent/cursor`) cannot publish until license decision is finalized
  and all package.json fields + root LICENSE updated atomically.

## Cross-repo dependencies

- **atlasent-api**: `packages/types/` is the source of truth for wire
  types; this SDK re-exports. `types-sync` CI in atlasent-api guards
  against drift.
- **atlasent-console**: imports `@atlasent/sdk` and `@atlasent/types`.
  Version-lock at the relevant SDK release.
- **atlasent-action**: bundles `@atlasent/sdk`. Pin at the relevant
  SDK release.
- **atlasent-examples**: imports published packages to demo real
  customer flow.

## Gaps (identified 2026-05-25)

- **Framework guard npm publish blocked** — three packages are
  code-complete but blocked on the org-wide Apache-2.0/MIT license
  decision.
- **Unified decision type** — TS and Python still diverge on the
  decision object shape; this confuses polyglot users.

## Framework guards (status)

- `@atlasent/langchain` — `withLangChainGuard(tools, client, opts)`
  wraps LangChain-style tool definitions with authorize-first execute.
  Zero dependency on `@langchain/core`. 13 tests green. **Not yet
  published.**

- `@atlasent/llamaindex` — `withLlamaIndexGuard(tools, client, opts)`
  wraps LlamaIndex-style tool definitions. Zero dependency on
  `llamaindex`. 13 tests green. **Not yet published.**

- `@atlasent/cursor` — `withCursorGuard(tools, client, opts)` wraps
  Cursor agent tools (MCP-style). Integrates with Cursor MCP server
  `CallToolRequestSchema` handlers. 13 tests green. **Not yet
  published.**

## Open questions

- Per-SDK SemVer cadence after the current publish arc: monthly minors
  or cut whenever features land?
- Do we publish `@atlasent/cli` on npm or keep it internal?
- License decision (Apache-2.0 vs MIT) — blocks framework guard
  publish.
