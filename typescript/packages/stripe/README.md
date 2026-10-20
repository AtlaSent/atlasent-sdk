# @atlasent/stripe — refund gate demo

An AtlaSent authorization gate in front of Stripe refunds, with the same
policy as the Shopify gate: refunds under $50 are issued automatically when
the order is delivered and within 30 days of delivery, larger ones go to a
manager, and every refund Stripe reports is checked against the permits the
gate issued.

`private: true`. This package is a demo and is not published to npm.

> **Status:** 58 unit tests over fakes of Stripe and the AtlaSent runtime.
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

## The alarm, and making the gate the only way to refund

Stripe has no hook to approve a refund before it is created, so
`refund.created` **detects** refunds made around the gate, from the
Dashboard or with another API key. It does not stop them:

- The signature is verified: `Stripe-Signature`, HMAC-SHA256 of
  `t.payload`, any `v1`, and a 5-minute replay window.
- A refund that is not `failed` or `canceled` must carry a gate reference
  that is in the ledger, not cancelled, and for the same PaymentIntent and
  amount. One refund per entry.
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

STRIPE_WEBHOOK_SECRET=whsec_... npm run webhook                 # alarm on :3001/webhooks/stripe
```

The CLI refuses live-mode keys (`sk_live_`, `rk_live_`). Forward webhooks
locally with `stripe listen --forward-to localhost:3001/webhooks/stripe`, and
subscribe a deployed endpoint to `refund.created`. The AtlaSent org needs the
same bundle and key scopes as the Shopify demo.

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

## What has not been verified

- Any call against a live Stripe account in test mode:
  - the PaymentIntent and refund field names on your account's API version
    (no `Stripe-Version` header is sent);
  - the `refund.created` event payload;
  - the exact restricted-key permissions.
- Any call against a live AtlaSent org, and the manager-approval path.
- PaymentIntents with more than one charge: only `latest_charge` is used.
- Account credits (see the note at the top).
