# Migration: Economic Governance — from `atlasent` to `atlasent-sdk`

**Status:** Active migration
**Started:** 2026-05-08
**Target completion:** Pre-enforcement layer rollout (item C in the EGAS audit)

---

## Why this migration exists

The canonical home for economic-governance Python primitives is
`atlasent-sdk/python/atlasent/governance/`. Earlier work (PR #155 / #156
in the `atlasent` orchestration repo) shipped an advisory subset there
to unblock test fixtures, but that copy:

- Lives in the wrong package (consumers `pip install atlasent`, not
  `atlasent-sdk`).
- Uses a 5-role liability taxonomy instead of the canonical 8.
- Numerically disagrees with the canonical TypeScript on every role
  weight.
- Lacks amount-threshold escalation, financial role requirements,
  regulator-approval threshold, dual-release threshold, and emergency
  freeze records on the quorum side.
- Lacks scope-aware budget limits, anonymous-agent gating, and
  multi-violation taxonomy on the budget side.
- Lacks action-type allowlist, per-type ceilings, risk-tier cap, bounds
  expiry, burst, and off-hours anomaly detection on the autonomous side.
- Has a non-byte-equivalent canonicalizer for evidence bundles, which
  prevents cross-language signature verification.

The canonical Python port in `atlasent-sdk/python/atlasent/governance/`
is introduced by this PR and supersedes the earlier copy.

For the full divergence analysis, see
the internal parity plan
`economic-governance-ts-python-parity-2026-05-08.md` (not public).

---

## Migration plan

### Phase 1 — Land canonical port (this PR)

- [x] Add `atlasent-sdk/python/atlasent/governance/` with all 5 priority
      modules (economic_evidence, liability_attribution, financial_quorum,
      budgetary_governance, autonomous_financial) plus shared helpers
      (financial_action, _canonical).
- [x] Add per-module Python tests covering parity-relevant behaviors
      (the divergence points the legacy module got wrong).
- [x] Add cross-language parity fixture at
      `compat/governance/fixtures/parity.json`.
- [x] Add Python and TypeScript compat tests reading the shared fixture.
- [x] Export `canonicalizeForEvidence` from `economicEvidence.ts` so the
      cross-language byte-equivalence test can verify the canonical TS
      implementation directly (rather than testing through
      `serializeSignableContent`).

### Phase 2 — Migrate consumers (next PR, separate from enforcement)

Consumers of the legacy `atlasent.governance` module (in the orchestration
repo) need to switch their imports.

**Old (in atlasent):**

```python
from atlasent.governance import classify_risk_tier, build_liability_chain
```

**New (atlasent-sdk's canonical port):**

In `atlasent-sdk` Python clients:

```python
from atlasent.governance import classify_risk_tier, build_liability_chain
```

(Same import path; consumers pull the canonical implementation by
upgrading their `atlasent` package once `atlasent-sdk` ships the new
minor version.)

The old in-repo `atlasent/python/atlasent/governance/` continues to work
until consumers migrate, but it should be marked deprecated.

### Phase 3 — Decommission the legacy module

Once all consumers are on the canonical port:

- Delete `atlasent/python/atlasent/governance/` from the orchestration
  repo.
- Remove or update `atlasent/packages/sdk/src/governance.ts` (the
  classification mirror used only by the old compat tests).
- Remove the duplicated `atlasent/compat/governance/fixtures/risk_tiers.json`
  in favor of the canonical `atlasent-sdk/compat/governance/fixtures/parity.json`.
- Drop the legacy compat test file in atlasent.

### Phase 4 — Build the enforcement layer (item C from the audit)

Not in scope for this migration. Once Phases 1–3 land, the enforcement
helpers (`enforce_financial_quorum`, `enforce_budget_constraint`,
`enforce_autonomous_bounds`) can ship against the now-locked canonical
primitives.

---

## Behavioral differences consumers should know

When migrating from the legacy `atlasent.governance` to the canonical
`atlasent-sdk` port, consumer code may need adjustment:

### Liability attribution

- Role names changed: `initiator` → `authorizer`. Five new roles available:
  `delegator`, `delegate`, `override_actor`, `supervisor`, `exception_approver`.
- Role weights changed: `executor` 0.20 → 0.25; `approver` 0.35 → 0.05;
  `auditor` and `system` removed from canonical taxonomy.
- `primary_accountable` (single-party getter) replaced by
  `find_primary_liability_parties(threshold=0.20)` (returns *all* parties
  at or above threshold).
- New: `validate_liability_chain` for structural integrity checks.
- New: `compute_chain_hash` for storage in the `chain_hash` column.

### Financial quorum

- Policy model changed from a string enum (`single_approver` /
  `simple_majority` / `two_thirds` / `unanimous`) to a structured
  `FinancialQuorumPolicy` with amount thresholds, role requirements, and
  regulator approval threshold.
- `recommend_quorum(risk_score)` is gone; recommendations now come from
  declared `amount_thresholds` and `financial_role_requirements`.
- Emergency freezes are now first-class records (`EmergencyFreeze`),
  not a per-evaluation boolean.

### Budgetary governance

- `BudgetConstraint` (legacy) has been split into `BudgetLimit`
  (scope-aware) and `SpendingConstraint` (action-type-aware). Consumers
  building either need both new types.
- The 4-string `BudgetResult` enum is replaced by typed
  `BudgetViolation` records; `check_budget_constraints` returns a
  structured result with `hard_blocks` and `soft_warnings` lists.

### Autonomous financial

- `ExecutionBounds.max_counterparty_exposure` is **not** in the canonical
  port. It existed only in the legacy module and was not in the
  migration DDL. If you depended on it, file an RFC to add the column
  and field properly.
- `is_3sigma_anomaly` is replaced by `detect_autonomous_anomaly` which
  also covers burst and off-hours anomalies.

### Economic evidence

- The legacy `EvidenceBundle` (a list of typed `EvidenceRecord`) is
  replaced by the structured `EconomicEvidenceBundle` (composite of
  execution + liability + quorum + budget + provenance).
- `bundle_hash` (legacy) is now `content_hash` (canonical SHA-256 over
  canonicalized signable content), with byte-equivalence to the TS
  implementation guaranteed by the cross-language fixture.
- Signing is unchanged: the bundle carries `signature` + `signing_key_id`
  fields; actual Ed25519 signing is the caller's responsibility (use the
  `cryptography` extra: `pip install 'atlasent[verify]'`).

---

## Cross-language parity guarantee

For the same input, the canonical Python and canonical TypeScript
implementations produce **identical** governance decisions. This is
enforced by:

1. The shared fixture at `compat/governance/fixtures/parity.json`.
2. The Python compat test
   `python/tests/governance/test_compat_fixtures.py`.
3. The TypeScript compat test
   `typescript/test/governance/canonicalCompat.test.ts`.

If either implementation diverges from the fixture, the corresponding
test fails. **That is a bug in the diverging implementation, not in the
fixture.** Fixture changes require updating both implementations in the
same PR.
