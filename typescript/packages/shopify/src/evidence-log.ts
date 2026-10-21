/**
 * The evidence log the report in @atlasent/refund-evidence reads: one JSON
 * record per line, `atlasent.refund_decision.v1` from the gate and
 * `atlasent.refund_alarm.v1` from the alarm. Set EVIDENCE_LOG to the same
 * path for the CLIs and the server, then build the report with
 * `npm run report -- --log <path>` in that package.
 *
 * Kept here, not imported from the report package, so this package installs
 * on its own. The report package's tests parse these records, so the two
 * cannot drift apart unnoticed. @atlasent/stripe carries the same file for
 * its own alarm.
 */

import { appendFileSync } from "node:fs";
import type { RefundDecisionRecord } from "./decision-record.js";
import type { RefundAuditVerdict, RefundWebhookPayload } from "./webhook.js";

export const REFUND_ALARM_SCHEMA = "atlasent.refund_alarm.v1" as const;

export interface RefundAlarmRecord {
  schema: typeof REFUND_ALARM_SCHEMA;
  at: string;
  system: "shopify";
  refund_id: string;
  target: string | null;
  amount_cents: number | null;
  currency: string | null;
  verdict: "authorized" | "unauthorized" | "ignored";
  reason: string | null;
  gate_ref: string | null;
}

/** The currency of the payload's refund transactions, when they all name the same one; otherwise unknown. */
function payloadCurrency(payload: RefundWebhookPayload): string | null {
  const codes = new Set(
    (payload.transactions ?? [])
      .map((t) => t.currency)
      .filter((c): c is string => typeof c === "string" && c.length > 0)
      .map((c) => c.toUpperCase()),
  );
  return codes.size === 1 ? [...codes][0]! : null;
}

/** The alarm's verdict on one refunds/create delivery, as a log record. */
export function alarmRecord(verdict: RefundAuditVerdict, payload: RefundWebhookPayload, at: Date): RefundAlarmRecord {
  return {
    schema: REFUND_ALARM_SCHEMA,
    at: at.toISOString(),
    system: "shopify",
    refund_id: verdict.refundId,
    target: `gid://shopify/Order/${verdict.orderId}`,
    amount_cents: verdict.amountCents,
    currency: payloadCurrency(payload),
    verdict: verdict.verdict,
    reason: verdict.verdict === "unauthorized" ? verdict.reason : null,
    gate_ref: verdict.gateRef ?? null,
  };
}

/** Appends one record as one line. Each write is a single small append, so concurrent writers do not interleave lines. */
export function appendEvidence(path: string, record: RefundDecisionRecord | RefundAlarmRecord): void {
  appendFileSync(path, JSON.stringify(record) + "\n");
}
