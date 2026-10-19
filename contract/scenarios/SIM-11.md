# SIM-11 — Permit revoked mid-flight

**Status:** fixture complete, tests pending implementation
**Fixture:** `SIM-11.json`

## Scenario

A permit is issued by `evaluate` but explicitly revoked by an admin
(via `POST /v1-permits/{id}/revoke`, ledger row D3) before the gate's
`verifyPermit` lands. `Enforce.run()` must deny with `reason_code:
permit_revoked`. `execute` must not run.

This is the runtime test for the cross-language `PermitOutcome`
discriminator wired in:
- atlasent-sdk PR #132 (Python `AtlaSentDeniedError.outcome`)
- atlasent-sdk PR #133 (TS `AtlaSentDeniedError.outcome`)
- atlasent-sdk PR #134 (Enforce `permit_revoked` ReasonCode)

If any link in that chain regresses — SDK strips the outcome,
Enforce taxonomy drops the value, adapter classifier mis-translates
— this scenario fails and the fail-closed property surfaces in CI
before any customer notices.

## Setup

- Single `Enforce` instance, single `run()` call.
- `evaluate` returns `allow` with permit token
  `pt_revoked_aabbcc`.
- `verify_permit` is a single response: HTTP 403 with `reason_code:
  permit_revoked` (the v1 server's response shape when
  `verified=false, outcome=permit_revoked`).

## Action

```
result = await enforce.run({ request, execute: spy })
```

## Expected

| Metric | Value |
|---|---|
| `decision` | `deny` |
| `reason_code` | `permit_revoked` |
| `execute_called` | `false` |
| `verify_permit_called` | `true` |

## Why this matters

A revoked permit is the operational lever for "stop this in flight"
— the leaked-actor scenario in `atlasent/docs/REVOCATION_RUNBOOK.md`
§ "Scenario 3". The runbook promises operators that a revoke takes
effect on the next verify. If Enforce silently maps `permit_revoked`
to a generic deny string, the operator can't tell from the audit log
what kind of denial happened, and the post-incident forensics chain
weakens.

By pinning `reason_code: permit_revoked` byte-identical to the
server response, this scenario locks the contract from
`POST /v1-permits/{id}/revoke` all the way to `EnforceRunResult.reasonCode`.
