/**
 * The evidence log the report in @atlasent/refund-evidence reads: one JSON
 * record per line, `atlasent.refund_decision.v1` from the gate and
 * `atlasent.refund_alarm.v1` from the alarm. Set EVIDENCE_LOG to the same
 * path for the CLI and the webhook server, then build the report with
 * `npm run report -- --log <path>` in that package.
 *
 * Kept here, not imported from the report package, so this package installs
 * on its own. The report package's tests parse these records, so the two
 * cannot drift apart unnoticed.
 */

import { appendFileSync } from "node:fs";
import type { RefundDecisionRecord } from "./decision-record.js";
import type { StripeRefund } from "./stripe.js";
import type { StripeRefundAuditVerdict } from "./webhook.js";

export const REFUND_ALARM_SCHEMA = "atlasent.refund_alarm.v1" as const;

export interface RefundAlarmRecord {
  schema: typeof REFUND_ALARM_SCHEMA;
  at: string;
  system: "stripe";
  refund_id: string;
  target: string | null;
  amount_cents: number | null;
  currency: string | null;
  verdict: "authorized" | "unauthorized" | "ignored";
  reason: string | null;
  gate_ref: string | null;
}

/** The alarm's verdict on one refund, as a log record. */
export function alarmRecord(verdict: StripeRefundAuditVerdict, refund: StripeRefund, at: Date): RefundAlarmRecord {
  const ignored = verdict.verdict === "ignored";
  return {
    schema: REFUND_ALARM_SCHEMA,
    at: at.toISOString(),
    system: "stripe",
    refund_id: verdict.refundId,
    target: ignored ? null : verdict.paymentIntent,
    amount_cents: ignored ? null : verdict.amountCents,
    currency: typeof refund.currency === "string" ? refund.currency.toUpperCase() : null,
    verdict: verdict.verdict,
    reason: verdict.verdict === "authorized" ? null : verdict.reason,
    gate_ref: ignored ? null : (verdict.gateRef ?? null),
  };
}

/** Appends one record as one line. Each write is a single small append, so concurrent writers do not interleave lines. */
export function appendEvidence(path: string, record: RefundDecisionRecord | RefundAlarmRecord): void {
  appendFileSync(path, JSON.stringify(record) + "\n");
}
