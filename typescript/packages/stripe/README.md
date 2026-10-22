# @atlasent/stripe — refund gate demo

An AtlaSent authorization gate in front of Stripe refunds, with the same
policy as the Shopify gate: refunds under $50 are issued automatically when
the order is delivered and within 30 days of delivery, larger ones go to a
manager, and every refund Stripe reports is checked against the permits the
gate issued.

`private: true`. This package is a demo and is not published to npm.

> **Status:** 106 unit tests over fakes of Stripe and the AtlaSent runtime.
> **Nothing here has been run against a live Stripe account or a live
> AtlaSent org yet.** See [What has not been verified](#what-has-not-been-verified).
>
> **Refunds only.** Account credits (customer balance) are not covered yet. A
> credit is not a payment going out, so which canonical action it should be
> evaluated as is a Canon decision, not one this package should guess.

## The pieces

| | What | Where |
|---|---|---|
| Gate | read payment and order → evaluate → verify → re-read → `POST /v1/refunds` | `src/guard.ts`, CLI `src/cli.ts` |
| Approval | resume an escalated refund once a manager decides it | `resumeApprovedStripeRefund` in `src/guard.ts`, `src/approvals.ts` |
| Alarm | every `refund.created` event is matched to a permit, or flagged | `src/webhook.ts`, `src/webhook-server.ts` |
| Stripe client | `GET /v1/payment_intents/:id`, `POST /v1/refunds`; no SDK dependency | `src/stripe.ts` |

## Where the facts come from

The policy is atlasent-api `examples/fake-store-refunds/policy.json` on the
org's `finance.payment.authorize` bundle; see the Shopify package's README
for the rule table.

- **From Stripe:**
  - the money: captured minus already refunded;
  - the currency, which must be USD for this policy;
  - whether the payment succeeded and whether the charge is disputed.
- **From the store's order system:** whether the goods were delivered, and
  when. Stripe doesn't know this. The store plugs in a `DeliveryFactsSource`
  (its Shopify store, warehouse system or database), keyed by the order
  reference it wrote into the PaymentIntent's `metadata.order_id` at
  checkout. That write happens server-side at checkout, never from the
  refund request.

Refused before AtlaSent is asked:

- an unknown or unsucceeded payment;
- a disputed charge;
- a payment with no order reference;
- a non-USD payment;
- more than is left to refund.

An order the store has no record of reaches the policy as `unknown`, and the
policy denies it as not delivered.

## How the gate binds a refund

- The refund (account, PaymentIntent, charge, order reference, amount,
  currency) is frozen and hashed. The digest goes to evaluate as
  `execution_payload_hash` and is re-presented at verify.
- The refund requires `verified` and `consumed`, is recorded in the ledger,
  and the payment and order are re-read before `POST /v1/refunds`.
- If the charge was disputed or refunded elsewhere in the meantime, the
  result is `payment_changed` and nothing is refunded.
- The random `gateRef` goes into the refund's `metadata.atlasent_gate_ref`
  **and** is used as Stripe's `Idempotency-Key`, so a retried call returns the
  first refund instead of creating a second.
- Any stop after the permit is recorded cancels the ledger entry. This
  includes a request error and a refund Stripe returns as `failed`. The
  permit token itself is never stored; the ledger keeps its SHA-256.

## When a refund goes to a manager

Refunds of $50 and up escalate. The runtime opens an approval request, and
the gate saves the refund exactly as it was evaluated (its snapshot and
digest) under that request's id, returned as `approvalRequestId`. A manager
decides it in the AtlaSent console. Then
`resumeApprovedStripeRefund` (or `npm run refund -- resume --approval <id>`)
checks the decision. It is single-shot, so call it again while the decision
is pending:

| Approval status | What happens |
|---|---|
| `pending` | `hold`; nothing changes |
| `approved` | the steps below |
| declined, expired, revoked, ... | `deny` with `APPROVAL_<STATUS>`; closed, nothing refunded |

On approval, every step must pass, or nothing is refunded:

1. re-read the payment and order, and recompute the digest; it must equal the
   frozen one, and the charge must not be disputed or refunded elsewhere;
2. claim the one permit the runtime minted for the approval
   (`POST /v1-approvals/{id}/claim-permit`), and check it is bound to that
   digest;
3. verify it, as the actor who asked for the refund, and require `consumed`;
4. record it in the ledger, re-read again, then `POST /v1/refunds`. The
   Idempotency-Key and `metadata.atlasent_gate_ref` are the escalated
   attempt's gateRef, so the alarm accounts for the refund.

This code cannot approve anything. It reads a person's decision and claims
the permit that decision produced. Only a refund this gate escalated can be
resumed, only once, and only for the Stripe account it was escalated on.

## The alarm, and making the gate the only way to refund

Stripe has no hook to approve a refund before it is created, so
`refund.created` **detects** refunds made around the gate, from the
Dashboard or with another API key. It does not stop them. Subscribe the
endpoint to `refund.updated` and `refund.failed` too: for a gated refund those
record the provider's status as an outcome observation (see the execution
contract below); they never vouch for a refund the gate did not authorize.

- The signature is verified: `Stripe-Signature`, HMAC-SHA256 of
  `t.payload`, any `v1`, and a 5-minute replay window.
- A refund that is not `failed` or `canceled` must carry a gate reference
  that is in the ledger, not cancelled, and for the same PaymentIntent and
  amount. One refund per entry.
- The CLI and the webhook server can share one `LEDGER_PATH`: every
  operation re-reads the file, and every write holds `<LEDGER_PATH>.lock`
  and replaces the file atomically. If the ledger cannot be read or locked,
  the refund is reported as unauthorized, never as authorized.
  A process killed while holding the lock leaves `<LEDGER_PATH>.lock` behind,
  and writes then fail closed until you delete it (with no refund process
  running). It is never taken over automatically.
- Anything else goes to `onUnauthorizedRefund`.

Prevention is about who holds refund rights:

- **API keys:** give the gate a **restricted key** with read access to
  PaymentIntents and Charges, and write access to Refunds. Make sure no other
  integration's key can create refunds.
- **Dashboard:** give team members roles that cannot issue refunds, so the
  gate is the only path. Stripe's role names and permissions change; confirm
  with a test teammate that a restricted role really cannot refund.

## Running it (test mode)

```sh
cd typescript/packages/stripe && npm ci

# Create a test-mode payment with metadata[order_id] (Dashboard, Stripe CLI or API), then:
cat > delivery.json <<'JSON'
{ "PPS-1001": { "order_status": "delivered", "delivered_at": "2026-10-15T12:00:00Z" } }
JSON

export STRIPE_SECRET_KEY=rk_test_... ATLASENT_API_KEY=... ATLASENT_ENVIRONMENT=test DELIVERY_FACTS_FILE=delivery.json
npm run refund -- facts  --payment pi_...                       # Stripe + delivery file only
npm run refund -- refund --payment pi_... --amount 18.99 --reason "arrived torn"
npm run refund -- resume --approval <id>                       # after a manager decides an escalation

STRIPE_WEBHOOK_SECRET=whsec_... npm run webhook                 # alarm on :3001/webhooks/stripe
```

The CLI refuses live-mode keys (`sk_live_`, `rk_live_`). Forward webhooks
locally with `stripe listen --forward-to localhost:3001/webhooks/stripe`, and
subscribe a deployed endpoint to `refund.created`. The AtlaSent org needs the
same bundle and key scopes as the Shopify demo.

## First live run, step by step (test mode)

You need three keys, kept apart on purpose:

| Key | Used by | Needs |
|---|---|---|
| `STRIPE_SETUP_KEY`, a test secret key `sk_test_...` | the seed script only | creating PaymentIntents |
| `STRIPE_SECRET_KEY`, a **restricted** test key `rk_test_...` | the gate | read PaymentIntents and Charges, write Refunds |
| `ATLASENT_API_KEY`, a test key | the gate | `evaluate:write`, `verify:execute`; plus `approvals:read` to resume escalated refunds, with the same key that asked |

1. **Load the policy** onto the AtlaSent test org's `finance.payment.authorize`
   bundle (atlasent-api `examples/fake-store-refunds/policy.json`), active for
   your `ATLASENT_ENVIRONMENT`.
2. **Pre-flight**, from `@atlasent/refund-evidence`:
   `npm run preflight -- --probe-policy --probe-escalation`. Decline the $72
   probe's approval request in the console.
3. **Seed five test payments:**
   `STRIPE_SETUP_KEY=sk_test_... STRIPE_SEED_CONFIRM=test-mode npm run seed-test-payments`.
   It writes `stripe-demo/delivery.json` (the stand-in order system) and
   prints one refund command per scenario. `--dry-run` shows the plan
   without calling Stripe. A re-run on the same day returns the same
   payments (idempotency keys); set `STRIPE_SEED_RUN_ID` for a fresh set.
4. **Run the five refunds** with the gate's restricted key:
   - $18.99 refunds;
   - $72 and $85 escalate, and each prints an `approvalRequestId`;
   - not-delivered and past-30-days are denied.
5. **Decide in the AtlaSent console:** approve the $72 request, decline the
   $85 one. Then run `npm run refund -- resume --approval <id>` for each. The
   $72 refunds; the $85 is closed as `APPROVAL_DENIED`.
6. **Bypass:** refund the $85 payment in the Stripe Dashboard. With
   `npm run webhook` running behind `stripe listen --forward-to
   localhost:3001/webhooks/stripe`, the alarm flags it, while the two gated
   refunds match their permits.

Set `EVIDENCE_LOG=$PWD/stripe-demo/evidence.jsonl` in every terminal before
step 4. After step 6, build the finance report from that log with
`npm run report` in `@atlasent/refund-evidence` (see [Evidence log](#evidence-log)).

Record what each step actually returned. Any step that differs from the list
above is a finding, not a demo to re-run until it passes.

## Evidence log

Pass `onDecision` to the gate to receive one `atlasent.refund_decision.v1`
record per decision, refunded or not. If the callback fails, the result
carries `logWarning`; the outcome never changes. The report and the
three-system demo that read these records are in `@atlasent/refund-evidence`.

The CLI and the webhook server write that log for you: set `EVIDENCE_LOG` to
the same file in both. The CLI appends one decision record per refund or
resume. The server appends one `atlasent.refund_alarm.v1` record per refund
Stripe reports: authorized, unauthorized or ignored. A failed write never
changes a decision or the webhook response; the server logs a
`verdict_not_logged` warning. Then build the report from
`@atlasent/refund-evidence`:

```sh
npm run report -- --log "$EVIDENCE_LOG" --store "Pinecone Pet Supply (fictional)"
```

## Tests

```sh
npm ci && npm run typecheck && npm test
```

The suite drives the real `AtlaSentClient` against the same fake runtime the
Shopify tests use, and a fake Stripe that honours idempotency keys. It was
checked against 14 specific defects, and each one made it fail:

- skipping the `consumed` check;
- refunding on escalate;
- verifying without the digest;
- ignoring a dispute, at the pre-check and at the re-read;
- allowing a payment with no order reference;
- a constant idempotency key;
- not cancelling the ledger entry;
- accepting a refund Stripe returned as `failed`;
- no signature replay window;
- the alarm ignoring the amount;
- alarming on failed refunds;
- counting "delivered" without a date;
- skipping PaymentIntent id validation.

The resume path was checked against eleven more, and each made it fail:

- skipping the digest check before the claim;
- skipping the claimed permit's binding check;
- skipping `consumed` on resume;
- treating any final status as approved;
- not closing the approval after the refund;
- skipping the account check;
- not cancelling the ledger entry on a stop;
- skipping the re-read after verify;
- verifying as the caller instead of the original actor;
- not saving the escalation;
- a resumed refund not keyed by its gateRef.

The evidence log was checked against five more, and each made it fail:

- a lowercase currency;
- no newline between records;
- the server not passing verdicts on;
- a failed log write breaking the webhook response;
- an ignored verdict recording an amount.

## What has not been verified

- Any call against a live Stripe account in test mode:
  - the PaymentIntent and refund field names on your account's API version
    (no `Stripe-Version` header is sent);
  - the `refund.created` event payload;
  - the exact restricted-key permissions.
- Any call against a live AtlaSent org, including the approval endpoints
  (`GET /v1-approvals/{id}`, `POST /v1-approvals/{id}/claim-permit`). The
  resume path follows the protocol `atlasent-action` and the MCP server use,
  against fakes only.
- Whether the runtime opens an approval request for an escalate on your org.
  If it returns no `approval_request_id`, there is nothing to resume.
- PaymentIntents with more than one charge: only `latest_charge` is used.
- Account credits (see the note at the top).

# Refund control hardening (2026-10-22)

The adapter now refuses missing/malformed charge amounts or dispute state,
inconsistent currency, a provider response for another payment, incomplete
refund-history reads, and existing pending/requires-action/unknown refunds.
The history read follows every page (bounded at 10,000 records, then refuses)
and runs again immediately before execution, including approval resumption.
Custom StripeApi implementations must implement listRefunds; a missing method
fails closed. Restricted keys need Refunds read as well as write.

The result's legacy refunded=true means Stripe accepted the request.
Use completion (succeeded, pending, requires_action) for its observed status.
Decision evidence now includes processor_status. Neither acceptance nor an
authorization proves final customer receipt; use authenticated events/readback.

This remains a demo adapter, not the complete refund-controls.v1 product.
It does not yet collect customer/order ownership, line-item tax/discount
allocation, credits outside Stripe, policy-specific return/service evidence,
budget reservations or a durable business-request identity across new calls.
A call without `businessRequestId` still creates a new gateRef; do not retry an
uncertain outcome that way (superseded for callers that pass one: see the
execution contract below). The final read reduces races but is not an atomic
reservation against refund paths that bypass this ledger. JsonFileLedger is local
demo storage. Dashboard refunds are detected by the alarm, not prevented.

The existing demo uses finance.payment.authorize; the Action Catalog uses
customer.refund.issue. This change intentionally does not rename either or
invalidate existing policy/approval bindings. A production adapter must target
the customer's actual installed action and prove its gate flags and evidence.

The detailed control profile is in the console's Issue refund catalog entry.
Its review-only policy builder lives in atlasent-api at
examples/fake-store-refunds/control-policy-builder.ts. That template never
allows, and is not silently installed by this adapter.

# Refund execution contract (2026-10-22, atlasent-api#4656)

What the adapter now enforces at the execution boundary, and what it still
does not. Proof level: local tests against fakes (`test/execution-contract.test.ts`,
29 cases) and six mutations that each make them fail. No Stripe test-mode
account and no AtlaSent org has run it.

## Durable business request identity

Pass `businessRequestId` (a ticket and line, a return authorization: 8-128 of
`A-Z a-z 0-9 . _ : -`). The gate reference, and so Stripe's Idempotency-Key, is
`gateRefForBusinessRequest(account, businessRequestId)`, the same in every
process. A later call with the same id never evaluates or submits again:

| Ledger state for that id | Answer |
|---|---|
| submitted and accepted | `duplicate_request`, with `existingRefundId` |
| submitted, outcome unknown | `unconfirmed`; reconcile, never a new request |
| escalated, approval open | `hold`, with the same `approvalRequestId` |
| authorized, then stopped | `duplicate_request`: a new decision needs a new id |
| denied or failed before authorization | decided again (nothing was authorized) |
| different payment or amount | `invalid_request` |

Repeats are not written to the decision log: they are not decisions.

## One in-flight refund per payment

`ledger.reserve` runs before anything is read or evaluated, under the file
lock for `JsonFileLedger`. A second refund on the same payment is refused
(`in_progress`) while the first is reserved: until it is accepted or stopped,
while its approval is open, or for as long as its submission is unconfirmed.
This serializes refunds that go through this ledger. It is not the
cross-payment cumulative budget (a runtime reservation, not built), and it
does not see refunds made with another key or in the Dashboard.

## Uncertain submissions are unconfirmed, not failed

`submitting` is recorded before `POST /v1/refunds`. Only HTTP 400/401/402/403/404
count as definitely not created (`submissionErrorIsDefinite`). A timeout, a lost
connection, 409, 429, 5xx, or a 2xx whose body cannot be read gives
`decision: "unconfirmed"`: the entry is NOT cancelled, the reservation stays,
and a `refund.created` for it is reported as authorized, because it is the
authorized refund. The decision log records outcome `unconfirmed`, which the
evidence report shows in its own tile, never as refunded or as nothing refunded.

## Reading the outcome back

`reconcileStripeRefund(stripe, gateRef, options, { resubmit? })` lists the
payment's refunds and finds the one carrying the gate reference (never matching
by amount alone). It records Stripe's status as a `readback` observation and
returns `succeeded`, `pending`, `requires_action`, `failed`, `canceled`,
`unconfirmed`, `not_issued`, `mismatch` (two refunds, another amount or payment,
or none after acceptance: an incident) or `read_failed`.

With `resubmit: true`, an unconfirmed refund that Stripe does not show is sent
again with the same Idempotency-Key and byte-identical parameters, only within
`RESUBMIT_WINDOW_MS` (1 h) of authorization and only if the payment and order
still carry exactly the authorized refund (same digest, not disputed, enough
left). Stripe returns the original refund if the first request created it. If
the charge balance already dropped, it is not resent, even if the list lags.
Outside those limits it stays unconfirmed for an operator.

Signature-verified `refund.created`/`refund.updated`/`refund.failed` events are
recorded once per event id as `event` observations, only for a refund that
matches its entry. Only `refund.created` runs the alarm, so a refund made
outside the gate is alerted and counted once. A lifecycle event records
nothing until `refund.created` (or the submission response, or a readback) has
established which refund the entry accounts for. A confirmed submission is
never regressed by a late local error.

If Stripe answers with a live refund that does not match the authorization
(another amount, charge, payment or currency), the entry is NOT cancelled: it
stays `unconfirmed` with the payment reserved, the alarm flags that refund, and
`reconcileStripeRefund` reports `mismatch`. Treat it as an incident. Observations keep every status in arrival order;
`latestProviderStatus` returns the last one. Stripe can report a refund as
failed after it succeeded, so read the observations, not one flag.

## Which action is evaluated

`actionType` defaults to `finance.payment.authorize`, with the digest unchanged
(binding v1), so existing approvals and permits are untouched. Set
`actionType: CUSTOMER_REFUND_ISSUE` only for an org whose installed action
class is `customer.refund.issue` (us-forprofit-baseline USFP-ACT-008). In the
Canon that slug is a proposed candidate (PAC-0045), not a minted CAR. With it,
evaluate and verify both use it and the digest is binding v2 (also binds the
business request id). An escalated refund resumes only under the action it was
escalated for. The adapter never maps one action onto the other.

## Still not covered here

- Order/customer ownership, return or service evidence, line-item
  tax/discount/shipping allocation and credits outside Stripe: not collected.
  The review-only policy in atlasent-api holds without them.
- Cumulative budgets across payments and a runtime-owned reservation: not built
  (runtime work). This ledger is local demo storage.
- Accounting and tax adjustments, and correlation to them.
- Any run against a Stripe test-mode account or an AtlaSent org.

