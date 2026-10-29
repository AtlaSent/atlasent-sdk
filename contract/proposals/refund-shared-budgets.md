# Additive shared refund reservation contract

Implementation dependency: [atlasent-api#4764](https://github.com/AtlaSent/atlasent-api/pull/4764),
`docs/REFUND_SHARED_BUDGETS.md` and its typed route/SQL fixtures. This proposal
does not modify `/v1-evaluate`, `/v1-verify-permit`, Permit or CDO wire shapes.

POST the existing `v1-consequential-operations` function's `/refund-reserve`
and `/refund-recheck` subroutes with `consequential_operations:write`.
The body contains exactly environment, provider_account, business_request_id,
payment_ref, nullable customer_ref, amount_minor (positive decimal integer
string, PostgreSQL bigint range) and currency (three lower case letters).
Recheck also supplies reservation_id (UUID). Organization/actor are derived by
the runtime authentication path, never supplied by the adapter. Provider is
fixed to Stripe. Credential environment must match the target environment.

HTTP 200 evidence has `ok: true`, `state: reserved`, `budget_status: enforced`,
`reservation_id`, `budget_remaining_minor` (non-negative integer string),
`authority_effect: none`, and `binding`: the exact submitted subject with
provider=stripe and reservation_id. The adapter validates every subject field
and requires recheck to name the same reservation. Conflicts/refusals and
unreadable receipts stop submission. Redirects are refused; calls have a 10s
default timeout and a 64KiB response-byte limit. Transport errors are sanitized.

Budget evidence grants no organizational authority, does not attest that the
provider account/credentials are isolated, and is not provider completion.
Canonical customer.refund.issue requires this client and a durable business
request. Legacy finance.payment.authorize remains opt-in for compatibility;
its original v1/v2 digest bytes and prior approvals are not migrated. Resuming
a canonical approval or resubmitting an unconfirmed canonical refund must
encounter the same budget boundary, even if current options omit an action.

Neither API exposes a caller-driven release/consume operation. Runtime RF4
verified provider settlement remains required, along with staging/native
acceptance; source/fake-provider tests do not close either requirement.
