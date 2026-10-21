# @atlasent/shopify — refund gate demo

An AtlaSent authorization gate in front of Shopify refunds, built for the
"Pinecone Pet Supply" demo: refunds under $50 are issued automatically when
the order is delivered and within 30 days of delivery, larger ones go to a
manager, and every refund is checked against the permits the gate issued.

`private: true`. This package is a demo and is not published to npm.

> **Status:** 140 unit tests over fakes of Shopify and the AtlaSent runtime.
> **Nothing here has been run against a live Shopify store or a live
> AtlaSent org yet.** The Shopify field names, mutations, token exchange and
> extension API follow Shopify's documented shapes as best known; check them
> against the API version you pin before the first live run. See
> [What has not been verified](#what-has-not-been-verified).

## The pieces

| | What | Where |
|---|---|---|
| **A** | The gate: read the order → evaluate → verify → re-read → `refundCreate` | `src/guard.ts`, CLI `src/cli.ts` |
| **A+** | Resume an escalated refund once a manager decides it | `resumeApprovedShopifyRefund` in `src/guard.ts`, `src/approvals.ts` |
| **B** | "Refund via AtlaSent" button on the Shopify order page, and its backend | `app/extensions/atlasent-refund/`, `src/server.ts` |
| **C** | Alarm: every `refunds/create` webhook is matched to a permit, or flagged | `src/webhook.ts`, `src/ledger.ts` |
| **D** | AI support agent whose only payment tool is the gate | `src/agent.ts`, CLI `src/agent-cli.ts` |

## The policy

The decision is made by the AtlaSent org's `finance.payment.authorize`
bundle, not by this package. The rules are atlasent-api
`examples/fake-store-refunds/policy.json` (first match wins, nothing matching
denies):

| Request | Decision |
|---|---|
| Missing, malformed or non-positive amount | deny `INVALID_REFUND_AMOUNT` |
| Condition 1: order not delivered | deny `ORDER_NOT_DELIVERED` |
| Days since delivery unknown | deny `RETURN_WINDOW_UNKNOWN` |
| Condition 2: more than 30 days since delivery | deny `RETURN_WINDOW_EXPIRED` |
| Under $50.00 | **allow** |
| $50.00 and up | escalate `MANAGER_APPROVAL_REQUIRED` |

The gate sends `amount_cents`, `currency`, `order_status`,
`days_since_delivery` and `refundable_cents`, all derived from the order as
Shopify reports it (`src/facts.ts`). Whoever asks for the refund supplies
only an order id and an amount:

- An order counts as **delivered** only when every non-cancelled fulfillment
  shows `DELIVERED` with a `deliveredAt` date.
- The 30 days run from the **last** delivery.
- A delivery date in the future leaves the window unknown, which denies.
- Only USD orders are accepted, because the thresholds are in USD cents.

## How the gate binds a refund

`guardedShopifyRefund` freezes the refund it will send: shop, order,
amount, currency, the parent payment and its gateway. It hashes that
snapshot. The digest goes to evaluate as `execution_payload_hash` and is
re-presented at verify, so a permit for $18.99 on one order cannot refund a
different amount, order or store.

Before `refundCreate`, all of these must hold. Any failure stops the refund:

- evaluate returned `allow`;
- verify returned `valid: true` **and** `consumed: true`;
- the ledger recorded the permit;
- a fresh read of the order still supports the refund. If the order was
  refunded elsewhere in the meantime, the result is `order_changed`.

The SDK's `permitId` is the permit token itself. The gate never writes it
anywhere: the ledger stores its SHA-256, and the Shopify refund note and
every response carry a random `gateRef` instead.

## When a refund goes to a manager

Refunds of $50 and up escalate. The runtime opens an approval request, and
the gate saves the refund exactly as it was evaluated (its snapshot and
digest) under that request's id, returned as `approvalRequestId`. A manager
decides it in the AtlaSent console. Then `resumeApprovedShopifyRefund`
checks the decision; the admin button shows **Check approval**, which calls
`POST /api/refunds/resume`, and the CLI has `resume --approval <id>`. It is
single-shot, so check again while the decision is pending:

| Approval status | What happens |
|---|---|
| `pending` | `hold`; nothing changes |
| `approved` | the steps below |
| declined, expired, revoked, ... | `deny` with `APPROVAL_<STATUS>`; closed, nothing refunded |

On approval, every step must pass, or nothing is refunded:

1. re-read the order and recompute the digest; it must equal the frozen one,
   with enough left to refund;
2. claim the one permit the runtime minted for the approval
   (`POST /v1-approvals/{id}/claim-permit`), and check it is bound to that
   digest;
3. verify it, as the staff member who asked for the refund, and require
   `consumed`;
4. record it in the ledger, re-read again, then `refundCreate`. The note
   carries the escalated attempt's gate reference, so the alarm accounts for
   the refund.

This code cannot approve anything. It reads a person's decision and claims
the permit that decision produced. Only a refund this gate escalated can be
resumed, only once, and only on the shop it was escalated on. The pending
approval lives in the ledger, so use `JsonFileLedger` (or a real store) if
the backend restarts between the request and the decision.

The SDK surfaces the runtime's `approval_request_id` as
`EvaluateResponse.approvalRequestId` (added with this demo; see the SDK
CHANGELOG). `managerApprovalStatus()` still reads the older HITL escalation
by `escalationId`.

## The alarm (C) and why staff permissions matter

Shopify has no hook that lets an app approve or block a refund made in the
Shopify admin before it happens; `refunds/create` arrives afterwards. So the
alarm **detects**, it does not prevent:

- The gate writes `AtlaSent gate ref <uuid>` into every refund note, and
  records the reference in the ledger before calling `refundCreate`.
- For each webhook (HMAC-verified), `auditRefundWebhook` requires all of the
  following:
  - the reference is in the ledger;
  - the order and amount match;
  - no other refund has already used that ledger entry.

  If the gate recorded a permit and then stopped (the order changed, or
  `refundCreate` failed), it cancels the ledger entry. The `gateRef` it
  returned can then never vouch for a refund made some other way.
  Refund transactions count when `SUCCESS` or `PENDING`, because
  asynchronous gateways send `refunds/create` before settlement.

  Anything else is `unauthorized` and goes to `onUnauthorizedRefund`, which
  the demo logs. In a real deployment, wire it to Slack, PagerDuty or email.
  A staff member copying a note onto another refund is flagged too.

  The CLI, the agent and the app server can share one `LEDGER_PATH`: every
  operation re-reads the file, and every write holds `<LEDGER_PATH>.lock`
  and replaces the file atomically. If the ledger cannot be read or locked,
  the refund is reported as unauthorized, never as authorized.
  A process killed while holding the lock leaves `<LEDGER_PATH>.lock` behind,
  and writes then fail closed until you delete it (with no refund process
  running). It is never taken over automatically.

**Prevention is a store setting:** remove the refund permission from staff
accounts (Shopify admin → Settings → Users → each staff member → order
permissions) so that the "Refund via AtlaSent" button is the only refund path
staff have. Shopify's permission names have changed over time. Check that the
current admin offers refunds as a separate permission, and confirm with a
test account that a restricted staff member cannot refund.

## Running it

### 1. Shopify development store and app

1. Create a free [Shopify Partner](https://www.shopify.com/partners) account
   and a development store.
2. Create an app with the Shopify CLI. Copy `app/shopify.app.toml` into it,
   fill in the `REPLACE_` values, and copy `app/extensions/atlasent-refund/`
   into its `extensions/`.
3. Install the app on the dev store. To get an Admin API access token for the
   CLIs and the seed script, follow Shopify's current docs; the way to create
   a single-store token has changed more than once.
4. Scopes: `read_orders` and `write_orders` for refunds. The seed script also
   needs fulfillment write scopes (e.g. `write_merchant_managed_fulfillment_orders`).
5. The gate never reads customer email, so it needs no protected-customer-data
   approval. The support agent (D) does read email, to check order ownership,
   and Shopify gates that field separately. Without the approval, Shopify
   returns an error for the agent's order reads and the agent refuses every
   order. That is the safe failure, but get the approval if you run D.

### 2. AtlaSent org

You need the following:

- An active `finance.payment.authorize` bundle carrying the policy above.
- An API key with `evaluate:write` and `verify:execute`.
- `ATLASENT_ENVIRONMENT` set to the environment the bundle is published for.

If the org's `finance.payment.authorize` action class has
`requires_independent_approval` or `requires_human_approval` set, small
refunds route to approval too. That is the runtime working as configured.

### 3. Seed the five scenarios

```sh
cd typescript/packages/shopify && npm ci
npm run seed-dev-store -- --dry-run      # prints the plan
SHOPIFY_SHOP=pinecone-demo.myshopify.com SHOPIFY_ADMIN_TOKEN=... \
SHOPIFY_SEED_CONFIRM=dev-store npm run seed-dev-store
```

Orders are paid with a `manual` gateway transaction, so refunds move no real
money. After creating each order, the script reads it back and prints what
the gate sees, for example `delivered, 5 days, refundable $34.99`. If a
delivered scenario reads `not_delivered`, the fulfillment event did not
register as a delivery on your API version.

### 4. A — one refund from the terminal

```sh
export SHOPIFY_SHOP=... SHOPIFY_ADMIN_TOKEN=... ATLASENT_API_KEY=... ATLASENT_ENVIRONMENT=test
npm run refund -- facts  --order <id>                          # Shopify only, no AtlaSent call
npm run refund -- refund --order <id> --amount 18.99 --reason "arrived torn"
```

### 5. B + C — the admin button and the alarm

```sh
SHOPIFY_CLIENT_ID=... SHOPIFY_CLIENT_SECRET=... SHOPIFY_SHOP=... \
ATLASENT_API_KEY=... ATLASENT_ENVIRONMENT=test npm run serve
```

Expose port 3000 at the app's `application_url` (for example with the
Shopify CLI tunnel), then `shopify app deploy`.

The backend handles the routes below. Admin API access comes from Shopify
token exchange, or from `SHOPIFY_ADMIN_TOKEN` if set. Token exchange requests
an expiring offline token and is cached only until shortly before it expires.
Each request carries a fresh session token, so an expired token is simply
exchanged again; no refresh token is stored.

| Route | Auth | Does |
|---|---|---|
| `POST /api/refunds` | session token, verified for signature, audience, expiry and shop | runs the gate as `shopify-staff:<shop>/<user>` |
| `POST /api/refunds/resume` | same | resumes an escalation by `approvalRequestId`; 501 if approvals are not configured |
| `POST /webhooks/refunds-create` | HMAC | runs the alarm |

### 6. D — the support agent

```sh
CUSTOMER_EMAIL=robin@example.com npm run agent    # plus the env from step 4, and Anthropic credentials
```

The agent runs on `claude-opus-5-5`, with server-side refusal fallback
enabled (`fallbacks: "default"`). It has two tools, `lookup_order` and
`issue_refund`, and both refuse orders that don't belong to
`CUSTOMER_EMAIL`. In a real store that email comes from the customer login,
never from the chat. The model can ask for any refund; the gate decides.

## Evidence log

Pass `onDecision` to the gate to receive one `atlasent.refund_decision.v1`
record per decision, refunded or not. If the callback fails, the result
carries `logWarning`; the outcome never changes. The report and the
three-system demo that read these records are in `@atlasent/refund-evidence`.

Set `EVIDENCE_LOG` to one file for the refund CLI, the support agent and the
server (`npm run serve`), and each writes it for you:
- every gate decision becomes an `atlasent.refund_decision.v1` record,
  including the admin button and resumed approvals;
- every `refunds/create` verdict becomes an `atlasent.refund_alarm.v1`
  record, with the currency only when the webhook states one.

A failed write never changes a decision or the webhook response; the server
logs a `verdict_not_logged` warning. Then, in `@atlasent/refund-evidence`:
`npm run report -- --log "$EVIDENCE_LOG" --store "Pinecone Pet Supply (fictional)"`.

## Tests

```sh
npm ci && npm run typecheck && npm test
```

The suite drives the real `AtlaSentClient` against a fake runtime that
applies the demo policy and permit binding, and uses an in-memory fake
Shopify. It was checked against sixteen specific defects, and each one made it
fail:

- skipping the `consumed` check;
- skipping the refundable re-check;
- refunding on escalate;
- verifying without the digest;
- the webhook ignoring the amount;
- skipping the token audience check;
- the agent ignoring order ownership;
- counting `DELIVERED` without a date as delivered;
- skipping the shop allowlist;
- skipping the refundable pre-check;
- not cancelling the ledger entry after a stop, and the webhook ignoring a
  cancelled entry;
- not counting `PENDING` refund transactions;
- reading the customer email on every order read;
- caching an expiring token past its expiry, and not requesting an expiring
  token.

The resume path was checked against ten more, and each made it fail:

- skipping the digest check before the claim;
- skipping the claimed permit's binding check;
- skipping `consumed` on resume;
- treating any final status as approved;
- not closing the approval after the refund;
- skipping the shop check;
- not cancelling the ledger entry on a stop;
- verifying as the caller instead of the original actor;
- not saving the escalation;
- a resumed refund note without the gate reference.

The evidence log was checked against five more, and each made it fail:

- guessing a currency when the transactions disagree;
- a lowercase currency;
- no newline between records;
- the server not passing verdicts on;
- a failed log write breaking the webhook response.

## What has not been verified

- Any call against a live Shopify store: the order query, `refundCreate`,
  the seed mutations, delivery events setting `deliveredAt`, token
  exchange, and webhook payload shape.
- The admin extension in a real admin: only a syntax check runs in CI. It is
  written for the React extension API (`api_version` 2025-07); newer
  versions use Preact and need a port.
- Whether relative `fetch("/api/refunds")` from the extension resolves to the
  app backend on your setup. If it doesn't, use the absolute app URL.
- Any call against a live AtlaSent org, including the approval endpoints
  (`GET /v1-approvals/{id}`, `POST /v1-approvals/{id}/claim-permit`). The
  resume path follows the protocol `atlasent-action` and the MCP server use,
  against fakes only.
- Whether the runtime opens an approval request for an escalate on your org.
  If it returns no `approval_request_id`, there is nothing to resume.
- The "Check approval" button in a real admin.
- Multi-payment orders: refunds go against the first successful payment.
- Whether `refundCreate` on your API version requires an idempotency key.
- The `expiring: "1"` token-exchange parameter and `expires_in` handling,
  against Shopify's current access-token docs.
