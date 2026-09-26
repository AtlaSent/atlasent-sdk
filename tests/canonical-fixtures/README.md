# Canonical Schema Conformance Fixtures

**Status:** Phase 2 of the cross-repo parity gate. See
the internal `PHASE-2-PARITY-PLAN.md`
in the canonical repo.

Each subdirectory corresponds to one of the five frozen canonical
schemas (vendored under `vendor/atlasent-canonical/v1-rc/`):

| Subdir | Schema |
|---|---|
| `evaluate-request/` | `evaluate-request.schema.json` |
| `decision-snapshot/` | `decision-snapshot.schema.json` |
| `permit/` | `permit.schema.json` |
| `audit-chain-entry/` | `audit-chain-entry.schema.json` |

`_common.schema.json` is referenced via `$ref` by the others — ajv
loads it as a side-schema.

## Filename convention

The conformance script reads filename prefix as the verdict:

- `valid_*.json` → MUST validate against the schema
- `rejected_*.json` → MUST NOT validate against the schema

Any other prefix is an error.

## What this gate proves (Phase 2 launch)

- Every fixture conforms (or is correctly rejected by) the canonical
  schema vendored at the pinned commit.
- Adding a fixture that doesn't pass under the current pin is a
  freeze break — the gate fails and the PR is blocked.

## What this gate does NOT yet prove (Phase 2.5)

- That this repo's hand-written types (`packages/types/src/index.ts`,
  `supabase/functions/_shared/types.ts`) round-trip the fixtures
  byte-identically. The round-trip check is the planned follow-up.

## Adding fixtures

1. Drop the file in the right subdir with the right prefix.
2. Run `scripts/run-canonical-conformance.sh` locally; it must pass.
3. Justify the fixture in the PR body (one line per fixture).

## Removing fixtures

During the convergence soak (until `schema/v1` promotion), the
fixture corpus is append-only. Removing or weakening a fixture
requires soak-restart authorization.
