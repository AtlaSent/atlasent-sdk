# CLAUDE.md

Project-level instructions for Claude Code working on `atlasent-sdk`.

## Architecture baseline

> Canonical cross-repo reference: [`atlasent-docs/architecture/ARCHITECTURE-BASELINE.md`](https://github.com/AtlaSent-Systems-Inc/atlasent-docs/blob/main/architecture/ARCHITECTURE-BASELINE.md)

This repo's role: **SDK layer** — thin wrappers around atlasent-api. Python (`atlasent` on PyPI) and TypeScript (`@atlasent/sdk` on npm), plus framework guards for LangChain, LlamaIndex, and Cursor.

Cross-repo invariants for this repo:
- Wire types source of truth is `atlasent-api/packages/types/`. SDK re-exports; never redefines independently.
- Any `/v1-evaluate` or `/v1-verify-permit` wire-shape change must go through `contract/schemas/` before SDK code changes.
- `contract/tools/drift.py` (drift detector) blocks CI if SDK types drift from API types.
- The canonical rule engine is `atlasent-api/packages/sdk/src/rules.ts` (its only byte-identical copy is `atlasent-api/supabase/functions/_shared/rules.ts`, kept in sync by the blocking `rules-sync` CI job **in atlasent-api**). This repo holds **no** `rules.ts` of its own — it consumes the engine via the published `@atlasent/sdk` package / re-export and never re-implements policy logic. Do not add a local `rules.ts`. See [ADR CROSS-002](https://github.com/AtlaSent-Systems-Inc/atlasent-docs/blob/main/architecture/adr/CROSS-002-rule-engine-single-source-of-truth.md).
- SDKs do NOT cache authorization decisions or re-implement policy logic.
- Publish mechanics: `@atlasent/sdk` and related packages release on `sdk-v*` tags; type-only changes on `types-v*` tags.

---

## Auto-open PRs when work reaches a natural stopping point

When a feature branch's work is **complete** (code committed, pushed to
origin, tests + lint + typecheck all green), proactively open a pull
request for it without waiting for an explicit "do PR" instruction.

A branch is "complete" when all of the following are true:
- The branch's intended scope is fully implemented.
- Every change is committed and pushed to `origin/<branch>`.
- All relevant checks pass locally (`pytest` for Python, `npm test` +
  `npm run typecheck` + `npm run build` for TypeScript, contract suite
  if contract files touched).
- A CHANGELOG entry has been added where appropriate, and version
  bumps are consistent across `_version.py` / `package.json` /
  CHANGELOG.

PR conventions:
- **Base branch**: `main` for standalone work; **the parent branch**
  for stacked work so reviewers see only the incremental diff
  (GitHub auto-updates the base to `main` once the parent merges).
- **Title**: under 70 characters, conventional-commit-style prefix
  (`feat(scope):`, `chore:`, `docs:`, `test:`, `fix:`). Use the
  first line of the head commit as a starting point.
- **Body**: Summary + Test plan sections. For stacked PRs, call out
  the dependency explicitly ("Stacked on PR #N — merge that first").
  For PRs bumping a shared version (e.g., Python `_version.py`) that
  may conflict with parallel branches, note the rebase ceremony.
- **End with the `session_...` footer** the Bash tooling rules
  already specify for `git commit` and `gh pr create` examples.
- **Do not open draft PRs** unless the user asks — the work shipped
  is ready for review.

At natural stopping points — a "stop", "wrap up", "done", "that's it",
or a user acknowledgment that the feature is finished — offer a short
summary of the opened PRs (numbers + titles + stacking relationship)
and stop. Don't keep proposing additional work unless asked.

Exceptions:
- If a branch has unresolved test failures, lint errors, or merge
  conflicts with its intended base, say so and ask before opening.
- If the commit is clearly a WIP (explicit `wip:` prefix,
  half-finished code), don't open the PR.
- If the user has asked to keep the branch local / private, respect
  that for the rest of the session.

## Branch naming

Follow the existing convention in this repo (`contract/SDK_COMPATIBILITY.md`
and recent history): `claude/<lang>-sdk-<topic>` for SDK-scoped work
(e.g., `claude/py-sdk-protect`, `claude/ts-sdk-hono-guard`), or
`claude/<topic>` for cross-cutting work (e.g.,
`claude/finish-work-...`, `claude/sdk-readme-protect-first`).

## Stacking

When a branch depends on another in-flight branch, cut it off the
parent (not off `main`). Open the PR with `base: <parent-branch>`.
Note the dependency in the PR body. This keeps reviewers' incremental
diffs honest and lets each PR merge cleanly once its base is in.

## Contract-first for wire changes

Anything that touches `/v1-evaluate` or `/v1-verify-permit` shapes
goes through `contract/schemas/` first. The SDK drift detector
(`contract/tools/drift.py`) catches drift from there. Do not invent
new endpoints, streaming formats, or bundle formats in the SDK
without a schema or a proposal in `contract/` first — see
`contract/README.md`'s "Adding / changing the contract" section.

## Coverage floors

- TypeScript: `vitest.config.ts` thresholds — keep lines ≥ 95%.
- Python: `pyproject.toml` `[tool.coverage.report] fail_under = 95`.
  Raise as new tests land; don't lower to paper over regressions.

## Disabled Endpoints

**Source of truth:** `atlasent-api/supabase/runtime-functions-disabled.json`.

> **Corrected 2026-09-26 — this section is stale in three ways; read this before the
> table below.** Checked against `atlasent-api` `main` (`ffb92cd`):
>
> 1. **Five entries left the disabled manifest on 2026-09-16 (atlasent-api#3402).**
>    `v1-sso-assertion-hook`, `v1-sso-providers`, `v1-policy-rules`,
>    `v1-policy-simulate-layered` and `v1-compliance-packs` now sit in
>    `runtime-functions.json` classified `quarantined`, because a quarantine
>    tombstone has to be *deployed* to be served. Their deployed handler is a
>    **410 Gone** tombstone rather than a 404 (live state is probed by
>    `atlasent-api`'s `quarantine-tombstone-drift` workflow; not re-checked
>    here). The rule for this repo is unchanged: do not call them.
> 2. **One entry is missing:** `v1-marketplace-install` (added 2026-09-10,
>    org-admin-only pack install, held back pending a security review).
> 3. **"No partial-rollout track" is no longer true.** Several notes below give
>    that as the reason a function is held back. `atlasent-api` now has
>    `supabase/runtime-functions-staging.json`, deployed only to staging for
>    functions classified `staging_only`; production deploys never read it. The
>    held-back functions are waiting on a founder decision, not a missing
>    mechanism (atlasent-docs CROSS-058, PROPOSED).
>
> The durable rule, instead of another count: check the `atlasent-api` manifests
> directly, relative to the runtime you target. An endpoint is unusable **anywhere**
> if it is in `runtime-functions-disabled.json` (not deployed) or in
> `runtime-functions.json` with `production_eligibility: quarantined` (deployed
> 410). An endpoint in `runtime-functions-staging.json` is deployed to the
> **staging runtime only**: callable when the configured base URL points at
> staging, absent in production. Do not ship a default code path that depends on
> it. Verified 2026-09-26: this repo references
> none of the endpoints named in this section.

**Corrected 2026-09-08 — the previous "8 entries, as of 2026-08-30" count in this
section had already drifted.** The live manifest has grown to **10 entries**: two
more were added after that date — `v1-compliance-packs` (quarantined 2026-09-06,
then retired permanently the same day, atlasent-api#2983) and
`v1-regulatory-interpretations` (added 2026-08-31, never deployed — see its notes
below). This is the same drift pattern the 2026-08-30 correction itself called
out (3 → 8); check the live manifest's `functions` array length directly rather
than trusting any count written here, including this one. Do not write new SDK
code that depends on any of these endpoints without first confirming they have
been re-enabled in the runtime manifest.

| Endpoint | SDK reference | Notes |
|---|---|---|
| `v1-sso-assertion-hook` | none currently | SSO SAML assertion hook — held back until SSO is in the V1 pilot surface |
| `v1-sso-providers` | none currently | SSO identity-provider management — held back; stale cross-reference to `v1-sso-connections` as a re-enable target removed 2026-08-10 (that function is now quarantined, not a re-enable target) |
| `v1-sso-connections` | none currently | QUARANTINED 2026-08-10 — real table-mismatch bug (POST wrote `sso_connections`; GET/:id, PATCH, DELETE read/wrote `identity_providers`). Do not re-enable without a redesign; `v1-sso` already implements this resource correctly |
| `v1-policy-rules` | none currently | QUARANTINED 2026-08-18 — plane-mismatch bug (same shape as ADR-032): every route reads/writes `public.policy_rules`, confirmed absent on runtime production (that table lives only in `atlasent-console`'s migrations). Do not re-enable by just adding the table; needs a plane-ownership redesign first |
| `v1-policy-simulate-layered` | none currently | QUARANTINED 2026-08-24 (#2181 follow-up) — same absent-on-runtime `policy_rules` dependency as `v1-policy-rules`, via its `bundle_id`-driven path. Same redesign prerequisite |
| `v1-compliance-packs` | none currently | QUARANTINED then RETIRED PERMANENTLY 2026-09-06 (atlasent-api#2983) — its install handler wrote columns (`org_id`/`policy_bundle`/`status`/`source`/`pack_id`/`pack_version`) that don't exist on `constraint_bundles`, so every install attempt had always failed; zero consumers, zero tests. Founder decision was retire, not adapt — do not build a `CompliancePackRule[]` adapter for it |
| `v1-control-assurance` | none currently | HELD BACK 2026-08-21 (CROSS-022) — fully implemented and tested, but kept out of `runtime-functions.json` because this repo's deploy model has no partial-rollout track and its `classification.json` production_eligibility is still experimental/disabled |
| `v1-internal-control-assurance-write` | none currently | HELD BACK 2026-08-21 (CROSS-022 step 4) — internal-worker-secret auth only; held back because no worker that calls it has been built yet, same manifest-has-no-partial-rollout reason as above |
| `v1-outcome-proposals` | none currently | HELD BACK 2026-08-27 (CROSS-042) — disabled-by-default AI Proposed Trajectories slice; production enablement requires first-party Anthropic/US-inference/ZDR attestation and security review not yet done |
| `v1-regulatory-interpretations` | none currently | NOT DEPLOYED (added 2026-08-31, CROSS-020 first-caller slice) — the migration backing its tables/RPCs has never been applied to any environment, its three new scopes (`regulatory_interpretations:read/write/ratify`) aren't seeded into `enterprise_permissions` yet, and a ratified row here grants no organizational authority (nothing on this route is read by `v1-evaluate`/`_shared/rules.ts`) |

Checked directly against `typescript/src/` and the Python SDK on 2026-09-08: no live
or dead references to either of the 2 newly-added entries above (or, re-confirmed,
the 5 added between 2026-08-18 and 2026-08-27).

> **`v1-sso` is shipped, not disabled** (re-enabled 2026-06-01) and is distinct from the
> three `v1-sso-*` skeletons above. The full `typescript/src/sso.ts` module (SSO
> connections, JIT rules, events, and the enforcement state machine) is live and wired as
> `client.sso`; it calls the deployed `/v1/sso/*` routes and does **not** carry a
> `// DISABLED:` comment. Do not add `v1-sso` to the table above.

> **Formerly-disabled, now re-enabled (2026-06-01) — do NOT re-add to the table:**
> `v1-redteam-runs`, `v1-post-evaluations`, `v1-spiffe-validate`, `v1-policy-bundles`,
> `v1-marketplace-packs`, `v1-decisions-stream`, `v1-transparency-anchor`. These 7 were on
> the original disabled list but are deployed today and present in `runtime-functions.json`.
> Note `v1-decisions-stream` (`typescript/src/client.ts` `subscribeDecisions()`) remains
> guarded by the `v2_decisions_stream` tenant feature flag even though it is deployed.

If you find a reference to a genuinely-disabled endpoint in new SDK code, add the comment `// DISABLED: This endpoint is not deployed in production. See atlasent-api/supabase/runtime-functions-disabled.json` and open a tracking issue before shipping the change.
