# @atlasent/shopify — refund gate demo

The default app previews an operator next step from a Shopify order read.
It requests `read_orders` only and cannot authorize or issue a refund.
The separate, explicit refund demo uses the existing AtlaSent authorization
gate; its policy and write-capable tools are described below.

`private: true`. This package is a demo and is not published to npm.

## Execution and recovery changes (2026-10-26)

The explicit write demo requires a stable `businessRequestId` on HTTP refund
requests, `--request-id` on CLI refunds, and a host-supplied `SUPPORT_CASE_ID`
for the agent CLI. Reuse the same upstream operation ID on retries; a model
cannot supply or replace the support tool's ID. This ID prevents duplicate
delivery; it does not prove customer intent or organizational authority.
The low-level guard retains its optional field for compatibility; callers
that omit it do not get business-request deduplication.

The existing ledger now interlocks scoped, unresolved executions on the same
payment. A send error, timeout, pending/failed transaction, missing readback,
or mismatched native transaction is `unconfirmed`, not “nothing happened.”
A new business ID does not bypass an unresolved execution. Only an exact
successful native refund transaction readback establishes `refunded: true`.
`refundCreate` returning an ID alone is not completion evidence.

`reconcileShopifyRefund` reads the original outcome without submitting another
refund. It is available as authenticated `POST /api/refunds/reconcile` with
`gateRef` and optional `candidateRefundId`, or:

```sh
npm run refund -- reconcile --gate-ref <gate-ref> --refund-id gid://shopify/Refund/123
```

The optional provider ID is only a lookup hint. The native order, note, parent
payment, amount, currency, gateway, transaction status and complete transaction
page must match the saved execution. Missing proof stays unconfirmed. A later
readback can also reconcile the approval's saved outcome.

Execution reads reject mismatched orders, full bounded pages, unresolved
payment/refund transactions, inconsistent currencies and split payments.
Evaluate sends the configured environment at both required locations.
Approval resume rejects another environment or changed evaluated facts.
**Older pending approvals without a saved facts hash must be re-evaluated;**
they cannot resume under this stricter source check. The permit binding
version and legacy `finance.payment.authorize` action remain unchanged.

These are local demo improvements, tested against fakes. The file ledger
requires one shared, trustworthy machine/filesystem and is not a multi-instance
transactional service, cumulative budget, signed provider event writer or
merchant self-service install. No all-path protection or production activation
follows from this change. The default server remains read-only.

> **Status:** Automated tests use fakes of Shopify and the AtlaSent runtime.
> **Nothing here has been run against a live Shopify store or a live
> AtlaSent org yet.** The Shopify field names, mutations, token exchange and
> extension API follow Shopify's documented shapes as best known; check them
> against the API version you pin before the first live run. See
> [What has not been verified](#what-has-not-been-verified).

## Post-purchase operations preview (read-only, not protection)

The default authenticated Shopify preview backend supports
`POST /api/operations/refund-preview` with the same verified Shopify session
token and allowlisted-shop boundary as the refund demo. Send
`{"orderId":"1001","amount":"18.99"}` as JSON with a Shopify session bearer
token. **Do not send customer identity, policy approval, or eligibility flags.**

The response is a preliminary operator next step, not a refund decision:

- `routine_candidate` — a simple delivered USD order has one observed payment
  and enough *observed* balance; **merchant eligibility, compensation, disputes,
  authority and full history still need verification**.
- `needs_attention` — a human should inspect fulfillment, payment allocation,
  currency, or apparent remaining amount.
- `unavailable` — the order is absent, malformed or its source data may be
  incomplete; do not assume the absence of disputes or refunds.

All responses state `authorization:not_evaluated`,
`execution:not_attempted`, `customer_notification:not_sent`, and list
missing proofs. The endpoint calls only `ShopifyAdmin.getOrder`; it does not
evaluate a runtime permit, create a refund, send email or install policy.
It refuses mismatched order identity, invalid sessions, other shops and
malformed amounts, and returns an unavailable response on provider failure.

**Important:** The current Shopify Admin query reads a maximum of 100
transactions and 50 fulfillments without full pagination; a full page is
marked unavailable. Even a shorter page does not establish complete refund,
dispute or compensation history. No customer-ownership or protected-data
scope has been validated by this read. A Shopify development-store integration,
approved read-only permissions and separate 14-control acceptance remain
open. The extension integration below is **not a customer-ready Commerce
Autopilot product**.

## Shopify order-action read-only first-value UI (unreleased)

The **AtlaSent order preview** action offers **Preview next step (read only)**.
It calls `POST /api/operations/refund-preview` with only the selected order ID
and requested amount. The response is accepted for display only when its
schema, read-only mode, explicit `not_evaluated`/`not_attempted`/`not_sent`
states, selected order, and exact cents match. It shows the operator next
step, missing proofs, source read timestamp, and an unassigned owner.
Changing the amount or selected order invalidates an in-flight/previous preview.
There is no refund request or approval-resume button in this extension.

### Run the read-only preview

1. Create a separate Shopify development app and copy `app/shopify.app.toml`
   plus `app/extensions/atlasent-refund/` into it. Fill in the `REPLACE_`
   values. The default config requests **only `read_orders`** and subscribes
   to no refund webhook. Do not reuse the write-demo app's credentials or an
   old write-capable install: a config change alone does not prove an existing
   token has lost previously granted scopes. Verify the installed scopes.
2. Install through Shopify's supported development-store consent flow. Keep
   the app client ID, secret, allowed shop and backend URL matched. Use test
   orders already present; the seed script is a separate write operation and
   needs its own permissions.
3. Start the preview server and expose port 3000 at `application_url`:

   ```sh
   SHOPIFY_CLIENT_ID=... SHOPIFY_CLIENT_SECRET=... SHOPIFY_SHOP=... npm run serve
   ```

   No `ATLASENT_API_KEY`, `ATLASENT_ENVIRONMENT`, permit ledger or approvals
   client is used. Every preview requires a verified Shopify session bearer
   token and an allowlisted shop. Admin API access comes from token exchange;
   for isolated development only, `SHOPIFY_ADMIN_TOKEN` can supply a token
   issued for that exact shop with order-read access.
4. Link/deploy the default Shopify app config, open a test order's **AtlaSent
   order preview** action, enter an amount, and request the preview. The server
   exposes only `POST /api/operations/refund-preview`, its `OPTIONS` preflight,
   and `GET /healthz` (`mode:read_only`). Refund, resume and webhook routes
   return 404, even with valid credentials. The write demo is available only
   through the explicit configuration and command below.

**This remains an unreleased integration slice.** Merchant-scoped OAuth/AtlaSent
tenant binding, a real development-store read, an AtlaSent Action Inbox handoff,
and independent 14-control/runtime acceptance remain required. No live install
or scope downgrade has been verified here. A preliminary `routine_candidate`
is not merchant eligibility or authorization. Do not publish this as a finished
Commerce Operations Autopilot product.

## Explicit Action Inbox Observe handoff (internal/staging integration)

This uses API [#4727](https://github.com/AtlaSent/atlasent-api/pull/4727)'s
`POST /v1-connectors/{id}/observations`, **not** the generic event ingest
route that also evaluates cross-system rules. Deploy and verify that runtime
route before running this integration. Source code is not deployment proof.

The normal `npm run serve` stays independent of AtlaSent and exposes no Inbox
write. The separate `npm run serve:inbox` command adds an explicit button after
a preview: **Add fresh preview to AtlaSent Inbox**. It displays the configured
runtime organization before submission. The server validates that destination,
re-reads the Shopify order and checks the AtlaSent key and current connector
before appending an observation. It never accepts a browser-supplied preview,
merchant eligibility, authority or destination override. A changed destination
requires reading the preview again.

Prerequisites for an authorized internal staging operator:

- An existing active runtime `custom` connector in the intended bound tenant,
  with `config.provider = "shopify"`, exact normalized `config.shop_domain`,
  and `environment` staging or sandbox. This config is a declared routing
  binding, **not proof of merchant/customer ownership or legal authority**.
- An already-authorized server credential with `connectors:read` and
  `connectors:write`. The latter is reserved (mint tier 3), unavailable to
  customer API keys. Do not broaden/mint a customer key to make the demo work.
  This is not the finished self-service merchant connection flow.
- Verify that the runtime organization is the destination selected by the
  console workspace's existing tenant-authority binding; never pick the first
  org. This command does not create/repair that binding or store credentials
  in a browser.

```sh
# Supply credentials through the authorized server environment, never source/URL/browser.
SHOPIFY_CLIENT_ID=... SHOPIFY_CLIENT_SECRET=... SHOPIFY_SHOP=... \
ATLASENT_INBOX_BASE_URL=https://YOUR_STAGING_RUNTIME/functions/v1 \
ATLASENT_INBOX_API_KEY=... ATLASENT_INBOX_ORG_ID=... \
ATLASENT_INBOX_CONNECTOR_ID=... ATLASENT_INBOX_ENVIRONMENT=test npm run serve:inbox
```

The Shopify app still needs only `read_orders`; no refund-write permission,
refund webhook, permit ledger or approval client is added. The provider session
and allowlisted shop are verified for every read and handoff. Preview reads more
than 60 seconds old are refused, including when destination checks take too long.
The receipt is accepted only for the exact organization, connector and observation
identity, with `authority_effect:none`, `execution:not_attempted` and
`verification:not_performed`.

Open the matching organization's Action Inbox **History** to see the observation.
It is not a pending approval. No automatic retry follows an uncertain submission;
check history before submitting again. Amount edits and Close are disabled while a
submission is pending. Its receipt or unconfirmed warning stays bound to the
submitted order, amount and organization even if Shopify changes the selected
order during the request. Separate submissions are separate
observations, not durable refund business requests or execution attempts.

This remains unverified against a real development store/runtime. Full merchant
consent and selected-org self-service installation, customer role/plan access,
revoked-consent/pagination acceptance, API #4656's 14 controls and native Stripe
TEST outcome/readback/export remain open. Do not call the product released.

## The pieces

| | What | Where |
|---|---|---|
| **A** | The gate: read the order → evaluate → verify → re-read → `refundCreate` | `src/guard.ts`, CLI `src/cli.ts` |
| **A+** | Resume an escalated refund once a manager decides it | `resumeApprovedShopifyRefund` in `src/guard.ts`, `src/approvals.ts` |
| **Preview** | Read-only Shopify order action and default backend | `app/extensions/atlasent-refund/`, `src/preview-server.ts` |
| **B** | Explicit write-demo backend, callable from the CLI or authenticated HTTP client | `src/server.ts`, `npm run serve:refund-demo` |
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
checks the decision. The explicit write-demo backend accepts
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

  A stop before submission (for example a changed order) cancels the entry.
  A send failure remains unresolved instead: the payment stays interlocked
  until native reconciliation. A webhook alone cannot resolve that outcome.
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
permissions) so that the approved gated tool is the only refund path staff have.
The default read-only extension does not expose that tool. Shopify's
permission names have changed over time. Check that the
current admin offers refunds as a separate permission, and confirm with a
test account that a restricted staff member cannot refund.

## Running the explicit write-capable refund demo

### 1. Shopify development store and app

1. Create a free [Shopify Partner](https://www.shopify.com/partners) account
   and a development store.
2. Create an app with the Shopify CLI. Copy `app/shopify.app.refund-demo.toml`
   into it as a separately named config,
   fill in the `REPLACE_` values, and use distinct credentials from the preview
   app. The shared order-action extension is preview-only; use the CLI or an
   authenticated HTTP client to request a demo refund.
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
- An API key with `evaluate:write` and `verify:execute`, plus `approvals:read` to resume escalated refunds. Resume with the same key that asked: only it may claim the permit.
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
npm run refund -- refund --order <id> --amount 18.99 --request-id case-123-refund --reason "arrived torn"
```

### 5. B + C — the explicit write backend and the alarm

```sh
SHOPIFY_CLIENT_ID=... SHOPIFY_CLIENT_SECRET=... SHOPIFY_SHOP=... \
ATLASENT_API_KEY=... ATLASENT_ENVIRONMENT=test npm run serve:refund-demo
```

Expose port 3000 at the app's `application_url` (for example with the
Shopify CLI tunnel), then deploy the explicit `refund-demo` config with
`shopify app deploy --config refund-demo`. Never use this config for read-only
onboarding.

The backend handles the routes below. Admin API access comes from Shopify
token exchange, or from `SHOPIFY_ADMIN_TOKEN` if set. Token exchange requests
an expiring offline token and is cached only until shortly before it expires.
Each request carries a fresh session token, so an expired token is simply
exchanged again; no refresh token is stored.

| Route | Auth | Does |
|---|---|---|
| `POST /api/refunds` | session token, verified for signature, audience, expiry and shop | requires `businessRequestId`; runs the gate as `shopify-staff:<shop>/<user>` |
| `POST /api/refunds/resume` | same | resumes an escalation by `approvalRequestId`; 501 if approvals are not configured |
| `POST /api/refunds/reconcile` | same | reads the exact original refund transaction and updates local outcome; never submits a refund |
| `POST /webhooks/refunds-create` | HMAC | runs the alarm |

### 6. D — the support agent

```sh
CUSTOMER_EMAIL=robin@example.com SUPPORT_CASE_ID=case-123-refund npm run agent
# plus the env from step 4 and Anthropic credentials; reuse this operation ID on retries
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
write-demo server (`npm run serve:refund-demo`), and each writes it for you:
- every gate decision becomes an `atlasent.refund_decision.v1` record,
  including authenticated demo requests and resumed approvals;
- every `refunds/create` verdict becomes an `atlasent.refund_alarm.v1`
  record, with the currency only when the webhook states one.

A failed write never changes a decision or the webhook response; the server
logs `decision_not_logged` or `verdict_not_logged`. A record with no stated
currency is reported as "currency unknown", never added to USD totals.

Then, in `@atlasent/refund-evidence`:
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
- Whether relative `fetch("/api/operations/refund-preview")` from the extension resolves to the
  app backend on your setup. If it doesn't, use the absolute app URL.
- Any call against a live AtlaSent org, including the approval endpoints
  (`GET /v1-approvals/{id}`, `POST /v1-approvals/{id}/claim-permit`). The
  resume path follows the protocol `atlasent-action` and the MCP server use,
  against fakes only.
- Whether the runtime opens an approval request for an escalate on your org.
  If it returns no `approval_request_id`, there is nothing to resume.
- The standalone preview and explicit write-demo servers in a live Shopify app.
- Multi-payment allocation is unsupported and refused by the execution guard.
- Native idempotency/version compatibility: the demo's older API pin and
  mutation do not send an `@idempotent` key. Current Shopify versions have
  different requirements; validate the exact pinned version before any native
  write. The local interlock never authorizes a provider resubmit. See
  [Shopify idempotent requests](https://shopify.dev/docs/api/usage/idempotent-requests).
- The new native refund readback query and reconciliation, in an actual store.
- The `expiring: "1"` token-exchange parameter and `expires_in` handling,
  against Shopify's current access-token docs.


