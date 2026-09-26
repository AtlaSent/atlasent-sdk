# ADRs in atlasent-sdk

This SDK repo is a **thin client layer** (per `CLAUDE.md`: SDKs do not cache
authorization decisions, re-implement policy logic, or own schema/migrations).
Architecture Decision Records are authored in the repo that owns the decision —
`atlasent` (contract authority), `atlasent-api` (system of record), or
`atlasent-docs` (canonical architecture). This directory should normally be
empty; SDK-scoped wire-shape decisions go through `contract/` instead.

## Registry note (2026-06-04)

`ADR-economic-governance-and-liability-attribution.md` in this directory is a
**non-authoritative duplicate**. The authoritative, system-of-record copy is
the internal API-side
`ADR-economic-governance-and-liability-attribution.md` (not public)
(it carries the table-level detail + machine-checkable invariants this copy
lacks, and the deployed system implements that version).

Two issues flagged in the 2026-06-04 cross-repo ADR audit:

1. **Divergence:** the liability-type enums differ between the two copies (this
   SDK copy: `individual/shared/delegated/supervisory/emergency_override`; the
   api copy: `sole_approver/shared_liability/delegated_liability/…`). The api
   copy governs.
2. **Misplacement:** an economic-governance *engine* with its own migrations and
   policy logic is out of category for a thin-client SDK repo. Per repo rules,
   that subsystem belongs in `atlasent-api` (runtime) and `atlasent` (contract),
   not here. Treat this file as historical; do not extend it in this repo.

The file is left in place (not deleted) to preserve history per the "don't
mutate an Accepted ADR" rule; this README is the authoritative annotation.
