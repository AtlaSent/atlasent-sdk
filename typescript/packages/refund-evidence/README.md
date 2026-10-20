# @atlasent/refund-evidence — evidence report and three-system demo

This package does three things for the refund gate demos:

- **The evidence report** a finance reader opens: every refund decision in a
  period, the rule that decided it, and every refund made around the gate. It
  is a self-contained HTML page plus a CSV.
- **A one-command demo**, `npm run demo`. It runs one refund policy across the
  Shopify gate, the support agent's refund tool and the Stripe gate. A
  manager then approves one escalation and declines the other. Two refunds
  are made around the gate, and the demo produces the report.
- **A pre-flight check**, `npm run preflight`, for the first live run: are the
  Shopify dev store, the Stripe test key and the AtlaSent test org set up the
  way the gates need?

`private: true`. This package is a demo and is not published to npm.

![Sample evidence report, built from simulated data](docs/sample-report.png)

## Run the demo

```sh
cd typescript/packages/refund-evidence && npm ci
npm run demo                                             # simulated stores + local policy stand-in
ATLASENT_API_KEY=... ATLASENT_ENVIRONMENT=test npm run demo   # simulated stores, real AtlaSent decisions
```

The demo writes `evidence-out/report.html`, `report.csv` and
`decisions.jsonl`, and prints each decision as it happens:

| Path | Request | Outcome |
|---|---|---|
| Shopify admin button | #PPS-1001 $18.99, delivered 5 days ago | Refunded |
| Shopify admin button | #PPS-1002 $72.00 | Sent to a manager |
| Shopify admin button | #PPS-1003 $12.00, in transit | Declined: not delivered |
| Shopify admin button | #PPS-1004 $25.00, 45 days after delivery | Declined: window expired |
| Agent's refund tool | #PPS-1005 $19.99, the signed-in customer's order | Refunded |
| Agent's refund tool | #PPS-1005, asked for by a different customer | Refused before the gate |
| Stripe gate | PPS-2001 $29.00 | Refunded |
| Stripe gate | PPS-2002 $85.00 | Sent to a manager |
| Manager approves | #PPS-1002 $72.00, resumed by the Shopify gate | Refunded, exactly as escalated |
| Manager declines | PPS-2002 $85.00, resumed by the Stripe gate | Declined by a manager |
| Around the gate | #PPS-1004 $25.00 in the Shopify admin, after the policy declined it | **Flagged** |
| Around the gate | pi_2002 $85.00 in the Stripe Dashboard, after the manager declined it | **Flagged** |

The demo uses the real Shopify and Stripe gate code (imported from the
sibling packages), but **the stores are always simulated** and no money
moves. Without an API key, decisions come from a local stand-in that applies
the same policy. The report says both things in a banner on its face, and
its audit references are placeholders.

The manager's decisions are simulated too: the local stand-in opens an
approval request for each escalation, as the runtime does, and the demo
plays the manager. **With a real API key, nobody is playing the manager.**
The demo leaves both escalations waiting and prints their approval request
ids. A person decides them in the AtlaSent console, and each is then resumed
with `npm run refund -- resume --approval <id>` in the Shopify or Stripe
package.

The agent path calls the agent's `issue_refund` tool directly, which is the
same code the Claude support agent runs. The model itself is not called. To
talk to the real agent, use `npm run agent` in `@atlasent/shopify`.

## Before the first live run

```sh
export ATLASENT_API_KEY=... ATLASENT_ENVIRONMENT=test
export SHOPIFY_SHOP=pinecone-demo.myshopify.com SHOPIFY_ADMIN_TOKEN=...   # optional
export STRIPE_SECRET_KEY=rk_test_...                                       # optional
npm run preflight                                    # 1. read-only
npm run preflight -- --probe-policy                  # 2. AtlaSent decides 3 sample refunds
npm run preflight -- --probe-policy --probe-escalation   # 3. and a $72 one
```

Each item reports PASS, FAIL or `--` (not checked), and the exit code is 1
on any failure.

| System | Checked | Not checkable from here |
|---|---|---|
| AtlaSent | key accepted; key is a `test` key; scopes `evaluate:write` + `verify:execute`; expiry | whether the key may claim an approved permit |
| AtlaSent, `--probe-policy` | allow under $50; deny not delivered; deny past 30 days. Each failure names the likely cause: no bundle, or an action class that routes everything to approval | |
| AtlaSent, `--probe-escalation` | $72 escalates **and** the runtime returns an approval request id, without which nothing can be resumed | |
| Shopify | token accepted; Partner development store; `read_orders`/`write_orders` | whether staff can still refund in the admin |
| Stripe | test-mode key (a live key is refused before any call); restricted, not full secret; can read PaymentIntents | refund write access; whether any other key or role can refund |

**What it changes.** Step 1 changes nothing. Steps 2 and 3 are real
evaluations, so each writes an audit entry. The allowed probe mints a permit
that is never used and expires. Step 3 opens an approval request a manager
will see: decline it. No step creates a refund or verifies a permit, and no
credential is printed. The key and org ids it shows are the ones
`/v1-api-key-self` returns for operator dashboards.

## Use the report with real gates

Both gates take an `onDecision` callback. It is called once per decision,
whether or not a refund ran, with an `atlasent.refund_decision.v1` record. If
the callback fails, the result carries `logWarning`; the outcome never
changes.

```ts
import { JsonlEvidenceLog } from "@atlasent/refund-evidence";
const log = new JsonlEvidenceLog("decisions.jsonl");
await guardedShopifyRefund(shopify, atlasent, request, { ...options, onDecision: (r) => log.append(r) });
```

Append alarm verdicts as `atlasent.refund_alarm.v1` records (see
`src/demo.ts`). Then build the report for a period:

```sh
npm run report -- --log decisions.jsonl --store "Pinecone Pet Supply" --from 2026-10-01 --to 2026-11-01
```

Lines that are not a known record are listed in the report, never silently
dropped.

## What the report is, and is not

- It **is** built from the gates' decision log, with every value
  HTML-escaped. In the CSV, a cell starting with `=` `+` `-` `@` gets a
  leading `'` so a spreadsheet does not run it as a formula.
- It is **not** itself signed. The proof is AtlaSent's signed audit export for
  the same period, verified with the offline verifier. The report says this
  in its "How to check this report" section, and lists AtlaSent's audit
  reference beside every decision that reached AtlaSent. A manager's decision
  on an escalation is its own row, marked "approval <id>": it was not a fresh
  evaluation, so it is checked against that approval request.
- Totals are kept per currency and never added across currencies.

## Tests

```sh
npm ci && npm run typecheck && npm test
```

The 36 tests cover:

- the summary, the period filter and per-currency totals;
- the simulated banner, present only when it applies;
- HTML escaping of hostile values, the CSV formula guard and quoting;
- log parsing, with rejected lines reported;
- manager-approved and manager-declined rows, their labels and approval
  references, and records written before approvals existed;
- the pre-flight checks, each pass and each failure, over fakes;
- the whole demo end to end, including that no permit token reaches the log
  or the report.

The suite was checked against twenty specific defects, and each one made it
fail:

- dropping `<` escaping;
- dropping the formula guard;
- merging currencies;
- an inclusive period end;
- dropping bad log lines silently;
- counting ignored alarm verdicts as outside the gate;
- the agent reading orders without their email;
- labelling a manager-approved refund "within policy";
- leaving `APPROVAL_*` codes unlabelled;
- showing "not evaluated" for a resumed decision;
- accepting a non-string approval request id;
- the demo's manager approving nothing;
- pre-flight accepting a live AtlaSent key;
- pre-flight not checking scopes;
- pre-flight ignoring the deny code;
- pre-flight passing an escalation with no approval request id;
- pre-flight accepting a live Stripe key;
- pre-flight not flagging a full secret key;
- pre-flight accepting a non-development store;
- pre-flight reporting ready despite a failure.

One defect was tried and did **not** make it fail: the stand-in letting a
permit be claimed for an approval that was not approved. The gates check the
approval status before they claim, so no test reaches that check in the
stand-in.
