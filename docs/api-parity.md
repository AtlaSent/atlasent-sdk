# SDK ↔ API Parity Matrix

**Status:** active · **Owner:** SDK + API · **Related gate:** the internal `V1_GATES.md` § G4

Every SDK method that crosses the wire MUST have a corresponding API handler
status tracked here. If the handler is `absent`, the method MUST NOT ship.
The check script (`scripts/check-api-parity.mjs`, wired into CI by
`.github/workflows/api-parity.yml`) enforces this on every PR.

## How registration works

The check is **opt-in by annotation** — it does not try to enumerate every
export in `typescript/src/` or `python/atlasent_sdk/`. Add the annotation:

```ts
// @hitl-method <slug>
export async function requestHumanApproval(...) { ... }
```

```py
# @hitl-method <slug>
def request_human_approval(...): ...
```

The slug appears as the **row key** in the matrix below. If the script finds
an annotation whose slug is missing from the matrix, CI fails. If the matrix
lists a slug whose handler status is `absent` AND the slug has live
annotations, CI also fails. Removing an annotation (or moving the row to
`handler: absent` after deprecating the API handler) cleans up the failure.

Why registration vs full enumeration: the SDK has 40+ source files and many
exports unrelated to HITL (helpers, types, middleware, retry, etc.). A full
enumerator would flag every helper and require denylisting most of them. The
registration pattern asks the author of a new HITL method to opt in once,
which is the actual point of the gate.

## Matrix

Format: each row maps an SDK method slug to its API handler status. Statuses:

- **`ga`** — API handler is on the V1 GA surface (post 2026-05-17).
- **`alpha`** — API handler exists but is alpha-only (under V3 Pillar 1
  alpha-endpoint surface; subject to change until the post-GA tag).
- **`absent`** — No API handler. Method MUST NOT have live `@hitl-method`
  annotations until the handler ships.

### TypeScript SDK (`typescript/src/`)

<!-- registry-start -->
<!--
  Format: `| slug | source-file:fn | handler-path | status | notes |`
  Add a row whenever you add `// @hitl-method <slug>` in a new TS export.
  Remove the row (or flip status) when the API handler lands or is removed.
-->

| Slug | Source | API handler | Status | Notes |
|---|---|---|---|---|
| _none registered_ | — | — | — | Existing HITL surfaces in `hitl.ts`, `approvalArtifact.ts`, `approvalQuorum.ts`, `regulatoryEscalation.ts` are pre-V1 and not registered yet; backfill on next touch. |

<!-- registry-end -->

### Python SDK (`python/atlasent_sdk/`)

<!-- python-registry-start -->

| Slug | Source | API handler | Status | Notes |
|---|---|---|---|---|
| _none registered_ | — | — | — | Same backfill plan as TS. |

<!-- python-registry-end -->

## Phase 2 SDK methods (evidence bundles, SCIM, multi-IdP auth)

These methods were added in the Phase 2 wave (branch
`claude/moores-law-execution-governance-m2m4o`, 2026-05-27). They do not use
the `@hitl-method` annotation mechanism (they are not HITL surfaces), so they
are listed here as a reference rather than in the registry block above.

### Evidence bundles (`/v1/evidence-bundles`)

| Method | TS source | Python source | API path | Status |
|---|---|---|---|---|
| `evidenceBundles.create` | `evidence-bundle.ts:create` | `evidence_bundle.py:create_evidence_bundle` | `POST /v1/evidence-bundles` | `alpha` |
| `evidenceBundles.get` | `evidence-bundle.ts:get` | `evidence_bundle.py:get_evidence_bundle` | `GET /v1/evidence-bundles/{bundleId}` | `alpha` |
| `evidenceBundles.download` | `evidence-bundle.ts:download` | `evidence_bundle.py:download_evidence_bundle` | `GET /v1/evidence-bundles/{bundleId}/download` | `alpha` |

### SCIM provisioning (`/scim/v2/*`)

| Method | TS source | Python source | API path | Status |
|---|---|---|---|---|
| `scim.users.list` | `scim.ts:users.list` | `scim_client.py:ScimUsersClient.list` | `GET /scim/v2/{orgId}/Users` | `ga` |
| `scim.users.create` | `scim.ts:users.create` | `scim_client.py:ScimUsersClient.create` | `POST /scim/v2/{orgId}/Users` | `ga` |
| `scim.users.update` | `scim.ts:users.update` | `scim_client.py:ScimUsersClient.update` | `PUT /scim/v2/{orgId}/Users/{id}` | `ga` |
| `scim.users.delete` | `scim.ts:users.delete` | `scim_client.py:ScimUsersClient.delete` | `DELETE /scim/v2/{orgId}/Users/{id}` | `ga` |
| `scim.groups.list` | `scim.ts:groups.list` | `scim_client.py:ScimGroupsClient.list` | `GET /scim/v2/{orgId}/Groups` | `ga` |
| `scim.groups.create` | `scim.ts:groups.create` | `scim_client.py:ScimGroupsClient.create` | `POST /scim/v2/{orgId}/Groups` | `ga` |
| `scim.groups.delete` | `scim.ts:groups.delete` | `scim_client.py:ScimGroupsClient.delete` | `DELETE /scim/v2/{orgId}/Groups/{id}` | `ga` |

### Multi-IdP token refresh (`/v1/auth/*`)

| Method | TS source | Python source | API path | Status |
|---|---|---|---|---|
| `auth.refresh` | `auth.ts:refresh` | `auth.py:refresh_token` | `POST /v1/auth/token/refresh` | `ga` |
| `auth.refreshWithIdp` | `auth.ts:refreshWithIdp` | `auth.py:refresh_with_idp` | `POST /v1/auth/idp/{idpId}/token/refresh` | `ga` |
| `auth.listIdpConnections` | `auth.ts:listIdpConnections` | `auth.py:list_idp_connections` | `GET /v1/auth/idp-connections` | `ga` |

### Simulation (placeholder — handler `absent`)

| Method | TS source | Python source | API path | Status |
|---|---|---|---|---|
| `simulation.run` | _(not yet implemented)_ | _(not yet implemented)_ | `POST /v1/simulation/run` | `absent` |

## Backfill plan (existing HITL surface)

The SDK already exports HITL-adjacent methods that predate this matrix:

- `typescript/src/hitl.ts`
- `typescript/src/approvalArtifact.ts`
- `typescript/src/approvalQuorum.ts`
- `typescript/src/regulatoryEscalation.ts`
- `typescript/src/v2.ts` (escalation paths, behavior-aware approval flows)
- `python/atlasent_sdk/` peers of the above (where they exist)

These ship today and the gate does not block their continued use. As each
module is touched in Wave C (V2_ROLLOUT.md), the next PR against it MUST:

1. Audit each exported function for HITL semantics (crosses the wire to a
   human-in-the-loop API surface).
2. Add `// @hitl-method <slug>` (or `# @hitl-method <slug>`) above each such
   export.
3. Add the corresponding row to the matrix above with the handler status.
4. If the handler status is `absent`, either ship the API handler in the
   same coordinated PR, or do not add the annotation.

A tracking issue for the backfill goes in V1_GATES.md G4 resolution log when
this matrix lands.

## V3 escalate decision

`AtlaSentEscalateError` (V3 Pillar 2 sketch in
the internal `V3_ROLLOUT.md`)
is NOT registered here. Adding it requires:

1. A V2-D11+ decision entry in
   the internal `V2_DECISIONS.md`
   locking the wire surface.
2. API handler ships.
3. SDK method added with `// @hitl-method escalate.v1` annotation.
4. Matrix row added with `status: ga`.

In that order. The gate enforces the order: an SDK export annotated with
an unregistered slug fails CI before publish.

## CI integration

The workflow `.github/workflows/api-parity.yml` runs
`scripts/check-api-parity.mjs` on every push and PR. Failure modes:

- **Annotation without matrix row** — `@hitl-method <slug>` found in source
  but no row with that slug in the matrix. Fix: add the row.
- **Matrix row with `status: absent` but live annotations** — the matrix
  records the handler as missing yet the SDK ships the method. Fix: ship
  the handler first, then update status; or remove the annotation.
- **Malformed matrix table** — the script can't parse the registry block.
  Fix: keep one row per line, preserve the `<!-- registry-start -->` /
  `<!-- registry-end -->` markers.

## Out of scope for this PR

- Cross-checking matrix `handler` paths against `openaispec/openapi.yaml`
  (validating that a row claiming `status: ga` actually has an OpenAPI
  operation at that path). Tracked as G4 phase 2; would require fetching
  `openaispec` as a CI dependency.
- Auto-generating matrix rows from JSDoc. Possible follow-up once the
  initial backfill establishes a stable annotation convention.
